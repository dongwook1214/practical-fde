//! The four sender pipelines under comparison.
//!
//! Every scheme is expressed as the same sequence of stages so that the CSV
//! columns line up:
//!
//! ```text
//!   encode -> commit -> encrypt -> sample -> subset -> sample_crypto -> kzg_proof
//! ```
//!
//! * `encode`        Reed--Solomon expansion of the file (identity for VECK).
//! * `commit`        the KZG commitment `C_phi` to the message polynomial.
//! * `encrypt`       whatever the sender does to *every* transmitted symbol.
//! * `sample`        Fiat--Shamir derivation of the `R` checked positions.
//! * `subset`        interpolation and commitment of the sampled polynomial.
//! * `sample_crypto` per-sample public-key work (VECK+: range proofs,
//!                   VECK*: the in-circuit ElGamal ciphertexts).
//! * `kzg_proof`     quotient, opening, and (VECK, VECK+) the DLEQ proof.
//!
//! The Groth16 part of VECK* and of our scheme is measured separately by the Go
//! driver in `benchmarks/snark`.

use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM as Msm};
use ark_ff::UniformRand;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{DenseUVPolynomial, EvaluationDomain, Polynomial};
use ark_std::test_rng;
use fde::dleq::Proof as DleqProof;
use fde::encrypt::elgamal::MAX_BITS;
use pfde_kzg::commit::kzg::{Kzg, Powers};
use pfde_kzg::veck::{
    compute_beta, interpolate_indices, subset_quotient_with_vanishing_poly, to_vanishing_poly,
    verify_subset_relation_with_vanishing_poly,
};
use sha3::Keccak256;
use std::time::{Duration, Instant};

use crate::config::{Config, Scheme};
use crate::elgamal;
use crate::encode::{code_lengths, encode};
use crate::mask;
use crate::report::{ms, Row, Writer};
use crate::sample;
use crate::srs;

type Poly<C> = DensePolynomial<<C as Pairing>::ScalarField>;

/// Cost of the linear, per-symbol stages measured once on a bounded prefix and
/// reused for every larger file size.  The work is identical per symbol, so the
/// only thing that changes between rows is the multiplier.
#[derive(Clone, Copy, Default)]
struct LinearRef {
    len: usize,
    encrypt_ms: f64,
    range_ms: f64,
}

/// Number of powers the range-proof machinery needs.
const RANGE_PROOF_POWERS: usize = MAX_BITS * 4;


/// The KZG half of every sampling scheme: the blinded (or plain) subset
/// polynomial, its quotient against the sampled vanishing polynomial, and the
/// opening at the Fiat--Shamir point.
///
/// Extracted so that `measure` and the tests in `crate::tests` exercise exactly
/// the same code path — a benchmark whose verifier is not the one being timed
/// proves nothing.
pub struct SubsetProof<C: Pairing> {
    pub vanishing: Poly<C>,
    pub subset_poly: Poly<C>,
    pub com_subset: C::G1,
    pub com_quotient: C::G1,
    pub alpha: C::ScalarField,
    pub value: C::ScalarField,
    pub opening: C::G1Affine,
    /// Time to build and commit the subset polynomial.
    pub subset_elapsed: Duration,
    /// Time to build the quotient, its commitment and the opening.
    pub proof_elapsed: Duration,
}

/// `blind` adds a degree-1 multiple of the vanishing polynomial, which hides the
/// sampled evaluations.  VECK and VECK+ must not blind: their DLEQ proof ties the
/// opened value to `sum_i L_i(alpha) x_i` exactly.
pub fn subset_proof<C: Pairing, R: ark_std::rand::Rng>(
    powers: &Powers<C>,
    encoded: &crate::encode::Encoded<C::ScalarField>,
    positions: &[usize],
    seed: &[u8; 32],
    blind: bool,
    rng: &mut R,
) -> Result<SubsetProof<C>, String> {
    let started = Instant::now();
    let vanishing: Poly<C> =
        DensePolynomial::from(to_vanishing_poly(positions.to_vec(), encoded.code_domain));
    let interpolated = interpolate_indices(&encoded.codeword, positions);
    let subset_poly: Poly<C> = if blind {
        let blinder = DensePolynomial::from_coefficients_vec(vec![
            C::ScalarField::rand(rng),
            C::ScalarField::rand(rng),
        ]);
        interpolated + &blinder * &vanishing
    } else {
        interpolated
    };
    let com_subset = powers.commit_g1(&subset_poly);
    let subset_elapsed = started.elapsed();

    let started = Instant::now();
    let quotient = subset_quotient_with_vanishing_poly(&encoded.poly, &subset_poly, &vanishing)
        .map_err(|err| err.to_string())?;
    let com_quotient = powers.commit_g1(&quotient);
    let alpha: C::ScalarField = sample::challenge_scalar(seed, b"alpha");
    let value = subset_poly.evaluate(&alpha);
    let opening = Kzg::<C>::proof(&subset_poly, alpha, value, powers);
    let proof_elapsed = started.elapsed();

    Ok(SubsetProof {
        vanishing,
        subset_poly,
        com_subset,
        com_quotient,
        alpha,
        value,
        opening,
        subset_elapsed,
        proof_elapsed,
    })
}

/// The buyer's two pairing checks: `phi - f_S` really is a multiple of the
/// sampled vanishing polynomial, and `f_S` really opens to `value` at `alpha`.
pub fn verify_subset_proof<C: Pairing>(
    powers: &Powers<C>,
    com_phi: C::G1,
    proof: &SubsetProof<C>,
) -> bool {
    verify_subset_relation_with_vanishing_poly::<C>(
        com_phi,
        proof.com_subset,
        proof.com_quotient,
        &proof.vanishing,
        powers,
    ) && Kzg::<C>::verify_scalar(
        proof.opening,
        proof.com_subset.into_affine(),
        proof.alpha,
        proof.value,
        powers,
    )
}

pub fn run<const N: usize, C>(cfg: &Config, writer: &mut Writer) -> Result<(), String>
where
    C: Pairing,
{
    let ell_max = 1usize << cfg.max_log;
    let r_max = cfg.subset_sizes.iter().copied().max().unwrap_or(0);
    let srs_range = (ell_max + 1).max(r_max + 2).max(RANGE_PROOF_POWERS);

    eprintln!(
        "[{}/{}] loading {} powers of tau from {}",
        cfg.scheme.tag(),
        cfg.curve.tag(),
        srs_range,
        cfg.srs_dir.display()
    );
    let (powers, srs_elapsed) = srs::load::<C>(&cfg.srs_dir, cfg.srs_chunk, srs_range)?;
    let range_powers = srs::fde_prefix(&powers, RANGE_PROOF_POWERS);
    eprintln!("      done in {:.2?}", srs_elapsed);

    let mut linear_ref: Option<LinearRef> = None;
    let rng = &mut test_rng();
    let encryption_sk = C::ScalarField::rand(rng);
    let encryption_pk = (<C::G1Affine as AffineRepr>::generator() * encryption_sk).into_affine();
    let mask_key = C::ScalarField::rand(rng);

    for log_ell in cfg.min_log..=cfg.max_log {
        let ell = 1usize << log_ell;
        let file: Vec<C::ScalarField> = (0..ell).map(|_| C::ScalarField::rand(rng)).collect();

        // Base VECK neither codes nor samples, so it has a single row per size.
        let subsets: Vec<usize> = if cfg.scheme.is_coded() {
            cfg.subset_sizes
                .iter()
                .copied()
                .filter(|&r| r + 2 < ell)
                .collect()
        } else {
            // Base VECK neither codes nor samples; `R = 0` records that.
            vec![0]
        };

        for r in subsets {
            let row = measure::<N, C>(
                cfg,
                &powers,
                &range_powers,
                &file,
                log_ell,
                r,
                encryption_sk,
                encryption_pk,
                mask_key,
                ms(srs_elapsed),
                &mut linear_ref,
            )?;
            eprintln!(
                "  ell=2^{:<2} R={:<5} prove={:>10.1} ms  verify={:>9}  {}",
                row.log_ell,
                row.r,
                row.prove_total_ms(),
                row.verify_ms
                    .map(|value| format!("{value:.1} ms"))
                    .unwrap_or_else(|| "-".to_string()),
                if row.extrapolated { "(extrapolated)" } else { "" },
            );
            writer.push(&row).map_err(|err| err.to_string())?;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn measure<const N: usize, C>(
    cfg: &Config,
    powers: &Powers<C>,
    range_powers: &fde::commit::kzg::Powers<C>,
    file: &[C::ScalarField],
    log_ell: u32,
    r: usize,
    encryption_sk: C::ScalarField,
    encryption_pk: C::G1Affine,
    mask_key: C::ScalarField,
    srs_load_ms: f64,
    linear_ref: &mut Option<LinearRef>,
) -> Result<Row, String>
where
    C: Pairing,
{
    let rng = &mut test_rng();
    let ell = file.len();
    // The redundancy must survive a grinding adversary that hashes up to
    // `2^grinding` candidate transcripts, hence `lambda + grinding` here.
    let beta = if cfg.scheme.is_coded() {
        compute_beta(r, cfg.lambda + cfg.grinding)
    } else {
        1.0
    };
    let (m, code_len) = code_lengths(ell, beta);

    let mut row = Row {
        scheme: cfg.scheme.tag().to_string(),
        curve: cfg.curve.tag().to_string(),
        log_ell,
        ell,
        r,
        lambda: cfg.lambda,
        beta,
        m,
        code_len,
        srs_load_ms,
        ..Row::default()
    };

    // ---- encode -----------------------------------------------------------
    let (encoded, encode_elapsed) = encode(file, code_len);
    row.encode_ms = ms(encode_elapsed);

    // ---- commit -----------------------------------------------------------
    let started = Instant::now();
    let com_phi = powers.commit_g1(&encoded.poly);
    row.commit_ms = ms(started.elapsed());

    let payload = &encoded.codeword.evals[..m];

    // How much of the payload the linear public-key stages are actually run on.
    let measured = match cfg.max_measured_log {
        Some(cap) => payload.len().min(1usize << cap),
        None => payload.len(),
    };
    row.measured_payload = measured;
    row.extrapolated = measured < payload.len();
    let scale = payload.len() as f64 / measured as f64;

    match cfg.scheme {
        Scheme::Ours | Scheme::VeckStar => {
            // ---- encrypt: symmetric PRF mask over the whole codeword -------
            let (_cipher, mask_elapsed) = mask::mask_encrypt(payload, mask_key);
            row.encrypt_ms = ms(mask_elapsed);

            // ---- sample ----------------------------------------------------
            let seed = sample::transcript_seed(&[com_phi.into_affine()]);
            let (positions, sample_elapsed) = sample::sample_positions(seed, m, r);
            row.sample_ms = ms(sample_elapsed);

            // ---- subset + kzg_proof ----------------------------------------
            let proof = subset_proof::<C, _>(powers, &encoded, &positions, &seed, true, rng)?;
            row.subset_ms = ms(proof.subset_elapsed);
            row.kzg_proof_ms = ms(proof.proof_elapsed);

            // ---- sample_crypto: VECK* re-encrypts the samples under ElGamal -
            let sampled_ciphertexts = if cfg.scheme == Scheme::VeckStar {
                let (ciphertexts, elapsed) =
                    elgamal::encrypt_positions::<N, C>(payload, &positions, &encryption_pk);
                row.sample_crypto_ms = ms(elapsed);
                Some(ciphertexts)
            } else {
                None
            };

            // ---- verify ----------------------------------------------------
            if cfg.verify {
                let started = Instant::now();
                let kzg_ok = verify_subset_proof::<C>(powers, com_phi, &proof);
                let samples_ok = sampled_ciphertexts
                    .as_ref()
                    .map(elgamal::verify_split_scalars)
                    .unwrap_or(true);
                row.verify_ms = Some(ms(started.elapsed()));
                row.verified = kzg_ok && samples_ok;
                assert!(row.verified, "verification failed for {}", cfg.scheme.tag());
            }
        }

        Scheme::VeckPlus => {
            // ---- encrypt: exponential ElGamal over the whole codeword -------
            let reference = linear_reference(linear_ref, measured, || {
                let (elapsed, _) =
                    elgamal::encrypt_streaming::<N, C>(&payload[..measured], &encryption_pk);
                LinearRef {
                    len: measured,
                    encrypt_ms: ms(elapsed),
                    range_ms: 0.0,
                }
            });
            row.encrypt_ms = reference.encrypt_ms * scale;

            // ---- sample ----------------------------------------------------
            let seed = sample::transcript_seed(&[com_phi.into_affine()]);
            let (positions, sample_elapsed) = sample::sample_positions(seed, m, r);
            row.sample_ms = ms(sample_elapsed);

            // ---- subset + kzg_proof ----------------------------------------
            // No blinding: VECK+ hides the samples with the ElGamal ciphertexts,
            // and the DLEQ below needs the opened value to equal
            // sum_i L_i(alpha) x_i exactly.
            let proof = subset_proof::<C, _>(powers, &encoded, &positions, &seed, false, rng)?;
            row.subset_ms = ms(proof.subset_elapsed);

            // Ciphertexts for the sampled positions, kept for the proof.
            let (ciphertexts, _) =
                elgamal::encrypt_positions::<N, C>(payload, &positions, &encryption_pk);

            // ---- sample_crypto: range proofs for the sampled shards --------
            let sampled_values: Vec<C::ScalarField> =
                positions.iter().map(|&index| payload[index]).collect();
            let (range_proofs, elapsed) =
                elgamal::prove_ranges::<N, C>(&sampled_values, range_powers);
            row.sample_crypto_ms = ms(elapsed);

            // ---- kzg_proof: the DLEQ tying the ciphertexts to the opening ---
            let points: Vec<C::ScalarField> = positions
                .iter()
                .map(|&index| encoded.code_domain.element(index))
                .collect();
            let started = Instant::now();
            let lagrange = sample::lagrange_coefficients(&points, proof.alpha);
            let q_point: C::G1 = Msm::msm_unchecked(&ciphertexts.random_points, &lagrange);
            let dleq = DleqProof::<C::G1, Keccak256>::new(
                &encryption_sk,
                q_point.into_affine(),
                <C::G1Affine as AffineRepr>::generator(),
                rng,
            );
            row.kzg_proof_ms = ms(proof.proof_elapsed) + ms(started.elapsed());

            // ---- verify ----------------------------------------------------
            if cfg.verify {
                let started = Instant::now();
                let kzg_ok = verify_subset_proof::<C>(powers, com_phi, &proof);
                let dleq_ok = check_dleq::<N, C>(
                    &dleq,
                    &ciphertexts,
                    &lagrange,
                    proof.value,
                    encryption_pk,
                    q_point,
                );
                let split_ok = elgamal::verify_split_scalars(&ciphertexts);
                let range_ok = elgamal::verify_ranges::<N, C>(&range_proofs, range_powers);
                row.verify_ms = Some(ms(started.elapsed()));
                row.verified = kzg_ok && dleq_ok && split_ok && range_ok;
                assert!(row.verified, "verification failed for veck-plus");
            }
        }

        Scheme::Veck => {
            // ---- encrypt + range-prove the whole file ----------------------
            let reference = linear_reference(linear_ref, measured, || {
                let (encrypt_elapsed, _) =
                    elgamal::encrypt_streaming::<N, C>(&payload[..measured], &encryption_pk);
                let (range_elapsed, _) =
                    elgamal::prove_ranges_streaming::<N, C>(&payload[..measured], range_powers);
                LinearRef {
                    len: measured,
                    encrypt_ms: ms(encrypt_elapsed),
                    range_ms: ms(range_elapsed),
                }
            });
            row.encrypt_ms = reference.encrypt_ms * scale;
            row.sample_crypto_ms = reference.range_ms * scale;

            // There is no subset: the buyer receives the whole file.
            let seed = sample::transcript_seed(&[com_phi.into_affine()]);
            let alpha: C::ScalarField = sample::challenge_scalar(&seed, b"alpha");

            // ---- kzg_proof: opening of phi plus the DLEQ -------------------
            let started = Instant::now();
            let value = encoded.poly.evaluate(&alpha);
            let opening = Kzg::<C>::proof(&encoded.poly, alpha, value, powers);
            let opening_elapsed = started.elapsed();

            let lagrange = encoded.code_domain.evaluate_all_lagrange_coefficients(alpha);

            // The DLEQ needs two size-`ell` multi-scalar multiplications, which
            // are linear in the file size just like the encryption, so they are
            // measured on the same reference prefix and scaled.  When the row is
            // extrapolated we never materialise the ciphertexts, so the MSM is
            // timed over SRS points instead: an MSM's cost depends on the number
            // of bases, not on where they came from.
            let ciphertexts = if row.extrapolated {
                None
            } else {
                let positions: Vec<usize> = (0..measured).collect();
                let (ciphertexts, _) =
                    elgamal::encrypt_positions::<N, C>(payload, &positions, &encryption_pk);
                Some(ciphertexts)
            };

            let started = Instant::now();
            let bases: &[C::G1Affine] = match ciphertexts.as_ref() {
                Some(ciphertexts) => &ciphertexts.random_points,
                None => &powers.g1[..measured],
            };
            let q_point: C::G1 = Msm::msm_unchecked(bases, &lagrange[..measured]);
            let dleq = DleqProof::<C::G1, Keccak256>::new(
                &encryption_sk,
                q_point.into_affine(),
                <C::G1Affine as AffineRepr>::generator(),
                rng,
            );
            let dleq_elapsed = started.elapsed();
            row.kzg_proof_ms = ms(opening_elapsed) + ms(dleq_elapsed) * scale;

            // ---- verify (only meaningful when nothing was extrapolated) -----
            if cfg.verify {
                if let Some(ciphertexts) = ciphertexts.as_ref() {
                    let (range_proofs, _) = elgamal::prove_ranges::<N, C>(payload, range_powers);
                    let started = Instant::now();
                    let opening_ok = Kzg::<C>::verify_scalar(
                        opening,
                        com_phi.into_affine(),
                        alpha,
                        value,
                        powers,
                    );
                    let dleq_ok = check_dleq::<N, C>(
                        &dleq,
                        ciphertexts,
                        &lagrange[..measured],
                        value,
                        encryption_pk,
                        q_point,
                    );
                    let split_ok = elgamal::verify_split_scalars(ciphertexts);
                    let range_ok = elgamal::verify_ranges::<N, C>(&range_proofs, range_powers);
                    row.verify_ms = Some(ms(started.elapsed()));
                    row.verified = opening_ok && dleq_ok && split_ok && range_ok;
                    assert!(row.verified, "verification failed for veck");
                }
            }
        }
    }

    Ok(row)
}

/// Reuse a cached measurement when the row only needs a scaled estimate.
fn linear_reference(
    slot: &mut Option<LinearRef>,
    len: usize,
    measure: impl FnOnce() -> LinearRef,
) -> LinearRef {
    if let Some(cached) = slot.filter(|cached| cached.len == len) {
        return cached;
    }
    let fresh = measure();
    *slot = Some(fresh);
    fresh
}

pub fn check_dleq<const N: usize, C: Pairing>(
    proof: &DleqProof<C::G1, Keccak256>,
    ciphertexts: &elgamal::Ciphertexts<N, C>,
    lagrange: &[C::ScalarField],
    opened_value: C::ScalarField,
    encryption_pk: C::G1Affine,
    q_point: C::G1,
) -> bool {
    let c_points: Vec<C::G1Affine> = ciphertexts
        .ciphers
        .iter()
        .map(|cipher| cipher.c1())
        .collect();
    let ct_point: C::G1 = Msm::msm_unchecked(&c_points, lagrange);
    let u_alpha = <C::G1Affine as AffineRepr>::generator() * opened_value;
    let q_star = ct_point - u_alpha;
    proof.verify(
        q_point.into_affine(),
        q_star,
        <C::G1Affine as AffineRepr>::generator(),
        encryption_pk.into_group(),
    )
}
