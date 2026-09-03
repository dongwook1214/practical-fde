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
use std::time::Duration;

use crate::timer::{measure, Limits, Sample};

/// `measure` for a stage that can fail: the error surfaces from the first run.
fn measure_fallible<T, E>(
    limits: Limits,
    mut f: impl FnMut() -> Result<T, E>,
) -> Result<(T, Sample), E> {
    let (result, sample) = measure(limits, &mut f);
    Ok((result?, sample))
}

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


/// The sampled subset polynomial and its commitment.
///
/// Split from the opening below so each half can be timed — and repeated —
/// independently, and so `measure` and the tests in `crate::tests` drive exactly
/// the same code.  A benchmark whose verifier is not the one being timed proves
/// nothing.
pub struct SubsetPoly<C: Pairing> {
    pub vanishing: Poly<C>,
    pub poly: Poly<C>,
    pub commitment: C::G1,
}

/// `blind` adds a degree-1 multiple of the vanishing polynomial, which hides the
/// sampled evaluations.  VECK and VECK+ must not blind: their DLEQ proof ties the
/// opened value to `sum_i L_i(alpha) x_i` exactly.
pub fn build_subset<C: Pairing, R: ark_std::rand::Rng>(
    powers: &Powers<C>,
    encoded: &crate::encode::Encoded<C::ScalarField>,
    positions: &[usize],
    blind: bool,
    rng: &mut R,
) -> SubsetPoly<C> {
    let vanishing: Poly<C> =
        DensePolynomial::from(to_vanishing_poly(positions.to_vec(), encoded.code_domain));
    let interpolated = interpolate_indices(&encoded.codeword, positions);
    let poly: Poly<C> = if blind {
        let blinder = DensePolynomial::from_coefficients_vec(vec![
            C::ScalarField::rand(rng),
            C::ScalarField::rand(rng),
        ]);
        interpolated + &blinder * &vanishing
    } else {
        interpolated
    };
    let commitment = powers.commit_g1(&poly);
    SubsetPoly {
        vanishing,
        poly,
        commitment,
    }
}

/// The quotient against the sampled vanishing polynomial and the opening at the
/// Fiat--Shamir point.
pub struct SubsetOpening<C: Pairing> {
    pub com_quotient: C::G1,
    pub alpha: C::ScalarField,
    pub value: C::ScalarField,
    pub opening: C::G1Affine,
}

pub fn open_subset<C: Pairing>(
    powers: &Powers<C>,
    encoded: &crate::encode::Encoded<C::ScalarField>,
    subset: &SubsetPoly<C>,
    seed: &[u8; 32],
) -> Result<SubsetOpening<C>, String> {
    let quotient =
        subset_quotient_with_vanishing_poly(&encoded.poly, &subset.poly, &subset.vanishing)
            .map_err(|err| err.to_string())?;
    let com_quotient = powers.commit_g1(&quotient);
    let alpha: C::ScalarField = sample::challenge_scalar(seed, b"alpha");
    let value = subset.poly.evaluate(&alpha);
    let opening = Kzg::<C>::proof(&subset.poly, alpha, value, powers);
    Ok(SubsetOpening {
        com_quotient,
        alpha,
        value,
        opening,
    })
}

/// The buyer's two pairing checks: `phi - f_S` really is a multiple of the
/// sampled vanishing polynomial, and `f_S` really opens to `value` at `alpha`.
pub fn verify_subset_proof<C: Pairing>(
    powers: &Powers<C>,
    com_phi: C::G1,
    subset: &SubsetPoly<C>,
    opening: &SubsetOpening<C>,
) -> bool {
    verify_subset_relation_with_vanishing_poly::<C>(
        com_phi,
        subset.commitment,
        opening.com_quotient,
        &subset.vanishing,
        powers,
    ) && Kzg::<C>::verify_scalar(
        opening.opening,
        subset.commitment.into_affine(),
        opening.alpha,
        opening.value,
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
    // G2 is only needed up to the degree of the sampled vanishing polynomial
    // (plus the blinder), and `g2_tau` for the opening check.
    let g2_range = (r_max + 2).max(RANGE_PROOF_POWERS);

    eprintln!(
        "[{}/{}] loading {} G1 and {} G2 powers of tau from {}",
        cfg.scheme.tag(),
        cfg.curve.tag(),
        srs_range,
        g2_range,
        cfg.srs_dir.display()
    );
    let (powers, srs_elapsed) = srs::load::<C>(&cfg.srs_dir, cfg.srs_chunk, srs_range, g2_range)?;
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
            let row = measure_row::<N, C>(
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
fn measure_row<const N: usize, C>(
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

    let limits = cfg.limits();
    // Sum of the absolute spreads of the repeated stages; divided by the row
    // total at the end, this bounds how much the total could have moved.
    let mut spread_ms = 0.0f64;
    let mut track = |sample: Sample| -> f64 {
        spread_ms += sample.spread_ms();
        sample.ms()
    };

    // ---- encode -----------------------------------------------------------
    let (encoded, sample) = measure(limits, || encode(file, code_len));
    row.encode_ms = track(sample);

    // ---- commit -----------------------------------------------------------
    let (com_phi, sample) = measure(limits, || powers.commit_g1(&encoded.poly));
    row.commit_ms = track(sample);

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
            // The round constants are public parameters, so they are built once
            // outside the timed region.
            let prf = mask::Prf::<C::ScalarField>::new();
            let (_cipher, sample) = measure(limits, || mask::mask_encrypt(&prf, payload, mask_key));
            row.encrypt_ms = track(sample);

            // ---- sample ----------------------------------------------------
            let seed = sample::transcript_seed(&[com_phi.into_affine()]);
            let (positions, sample) = measure(limits, || sample::sample_positions(seed, m, r));
            row.sample_ms = track(sample);

            // ---- subset ----------------------------------------------------
            let (subset, stat) =
                measure(limits, || build_subset::<C, _>(powers, &encoded, &positions, true, rng));
            row.subset_ms = track(stat);

            // ---- kzg_proof -------------------------------------------------
            let (opening, stat) = measure_fallible(limits, || {
                open_subset::<C>(powers, &encoded, &subset, &seed)
            })?;
            row.kzg_proof_ms = track(stat);

            // ---- sample_crypto: VECK* re-encrypts the samples under ElGamal -
            let sampled_ciphertexts = if cfg.scheme == Scheme::VeckStar {
                let (ciphertexts, stat) = measure(limits, || {
                    elgamal::encrypt_positions::<N, C>(payload, &positions, &encryption_pk)
                });
                row.sample_crypto_ms = track(stat);
                Some(ciphertexts)
            } else {
                None
            };

            // ---- verify ----------------------------------------------------
            if cfg.verify {
                let (ok, stat) = measure(limits, || {
                    verify_subset_proof::<C>(powers, com_phi, &subset, &opening)
                        && sampled_ciphertexts
                            .as_ref()
                            .map(elgamal::verify_split_scalars)
                            .unwrap_or(true)
                });
                row.verify_ms = Some(track(stat));
                row.verified = ok;
                assert!(ok, "verification failed for {}", cfg.scheme.tag());
            }
        }

        Scheme::VeckPlus => {
            // ---- encrypt: exponential ElGamal over the whole codeword -------
            let reference = linear_reference(linear_ref, measured, || {
                let (_, stat) = measure(Limits::once(), || {
                    elgamal::encrypt_streaming::<N, C>(&payload[..measured], &encryption_pk)
                });
                LinearRef {
                    len: measured,
                    encrypt_ms: stat.ms(),
                    range_ms: 0.0,
                }
            });
            row.encrypt_ms = reference.encrypt_ms * scale;

            // ---- sample ----------------------------------------------------
            let seed = sample::transcript_seed(&[com_phi.into_affine()]);
            let (positions, stat) = measure(limits, || sample::sample_positions(seed, m, r));
            row.sample_ms = track(stat);

            // ---- subset ----------------------------------------------------
            // No blinding: VECK+ hides the samples with the ElGamal ciphertexts,
            // and the DLEQ below needs the opened value to equal
            // sum_i L_i(alpha) x_i exactly.
            let (subset, stat) = measure(limits, || {
                build_subset::<C, _>(powers, &encoded, &positions, false, rng)
            });
            row.subset_ms = track(stat);

            let (opening, stat) = measure_fallible(limits, || {
                open_subset::<C>(powers, &encoded, &subset, &seed)
            })?;
            let open_ms = track(stat);

            // Ciphertexts for the sampled positions, kept for the proof.  A
            // streaming prover already holds these from the pass above, so they
            // are rebuilt but not charged again.
            let ciphertexts =
                elgamal::encrypt_positions::<N, C>(payload, &positions, &encryption_pk);

            // ---- sample_crypto: range proofs for the sampled shards --------
            let sampled_values: Vec<C::ScalarField> =
                positions.iter().map(|&index| payload[index]).collect();
            let (range_proofs, stat) = measure(limits, || {
                elgamal::prove_ranges::<N, C>(&sampled_values, range_powers)
            });
            row.sample_crypto_ms = track(stat);

            // ---- kzg_proof: the DLEQ tying the ciphertexts to the opening ---
            let points: Vec<C::ScalarField> = positions
                .iter()
                .map(|&index| encoded.code_domain.element(index))
                .collect();
            let ((lagrange, q_point, dleq), stat) = measure(limits, || {
                let lagrange = sample::lagrange_coefficients(&points, opening.alpha);
                let q_point: C::G1 = Msm::msm_unchecked(&ciphertexts.random_points, &lagrange);
                let dleq = DleqProof::<C::G1, Keccak256>::new(
                    &encryption_sk,
                    q_point.into_affine(),
                    <C::G1Affine as AffineRepr>::generator(),
                    &mut test_rng(),
                );
                (lagrange, q_point, dleq)
            });
            row.kzg_proof_ms = open_ms + track(stat);

            // ---- verify ----------------------------------------------------
            if cfg.verify {
                let (ok, stat) = measure(limits, || {
                    verify_subset_proof::<C>(powers, com_phi, &subset, &opening)
                        && check_dleq::<N, C>(
                            &dleq,
                            &ciphertexts,
                            &lagrange,
                            opening.value,
                            encryption_pk,
                            q_point,
                        )
                        && elgamal::verify_split_scalars(&ciphertexts)
                        && elgamal::verify_ranges::<N, C>(&range_proofs, range_powers)
                });
                row.verify_ms = Some(track(stat));
                row.verified = ok;
                assert!(ok, "verification failed for veck-plus");
            }
        }

        Scheme::Veck => {
            // ---- encrypt + range-prove the whole file ----------------------
            let reference = linear_reference(linear_ref, measured, || {
                let (_, encrypt_stat) = measure(Limits::once(), || {
                    elgamal::encrypt_streaming::<N, C>(&payload[..measured], &encryption_pk)
                });
                let (_, range_stat) = measure(Limits::once(), || {
                    elgamal::prove_ranges_streaming::<N, C>(&payload[..measured], range_powers)
                });
                LinearRef {
                    len: measured,
                    encrypt_ms: encrypt_stat.ms(),
                    range_ms: range_stat.ms(),
                }
            });
            row.encrypt_ms = reference.encrypt_ms * scale;
            row.sample_crypto_ms = reference.range_ms * scale;

            // There is no subset: the buyer receives the whole file.
            let seed = sample::transcript_seed(&[com_phi.into_affine()]);
            let alpha: C::ScalarField = sample::challenge_scalar(&seed, b"alpha");

            // ---- kzg_proof: opening of phi plus the DLEQ -------------------
            let ((value, opening), stat) = measure(limits, || {
                let value = encoded.poly.evaluate(&alpha);
                let opening = Kzg::<C>::proof(&encoded.poly, alpha, value, powers);
                (value, opening)
            });
            let open_ms = track(stat);

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
                Some(elgamal::encrypt_positions::<N, C>(
                    payload,
                    &positions,
                    &encryption_pk,
                ))
            };

            let bases: &[C::G1Affine] = match ciphertexts.as_ref() {
                Some(ciphertexts) => &ciphertexts.random_points,
                None => &powers.g1[..measured],
            };
            let ((q_point, dleq), stat) = measure(limits, || {
                let q_point: C::G1 = Msm::msm_unchecked(bases, &lagrange[..measured]);
                let dleq = DleqProof::<C::G1, Keccak256>::new(
                    &encryption_sk,
                    q_point.into_affine(),
                    <C::G1Affine as AffineRepr>::generator(),
                    &mut test_rng(),
                );
                (q_point, dleq)
            });
            row.kzg_proof_ms = open_ms + track(stat) * scale;

            // ---- verify (only meaningful when nothing was extrapolated) -----
            if cfg.verify {
                if let Some(ciphertexts) = ciphertexts.as_ref() {
                    let range_proofs = elgamal::prove_ranges::<N, C>(payload, range_powers);
                    let (ok, stat) = measure(limits, || {
                        Kzg::<C>::verify_scalar(
                            opening,
                            com_phi.into_affine(),
                            alpha,
                            value,
                            powers,
                        ) && check_dleq::<N, C>(
                            &dleq,
                            ciphertexts,
                            &lagrange[..measured],
                            value,
                            encryption_pk,
                            q_point,
                        ) && elgamal::verify_split_scalars(ciphertexts)
                            && elgamal::verify_ranges::<N, C>(&range_proofs, range_powers)
                    });
                    row.verify_ms = Some(track(stat));
                    row.verified = ok;
                    assert!(ok, "verification failed for veck");
                }
            }
        }
    }

    let total = row.prove_total_ms();
    row.spread_pct = if total > 0.0 {
        spread_ms / total * 100.0
    } else {
        0.0
    };

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
