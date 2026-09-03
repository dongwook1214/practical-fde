//! Correctness tests for the benchmark pipeline.
//!
//! A benchmark that asserts its own verifier accepts proves nothing unless the
//! verifier also *rejects*.  These tests drive the same functions `schemes::run`
//! does and check both directions.

use ark_bls12_381::Bls12_381 as C;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM as Msm};
use ark_ff::{FftField, UniformRand};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{DenseUVPolynomial, EvaluationDomain, Polynomial};
use ark_std::test_rng;
use pfde_kzg::commit::kzg::Powers;
use sha3::Keccak256;

use crate::encode::{code_lengths, encode};
use crate::mask;
use crate::sample;
use crate::schemes::{check_dleq, subset_proof, verify_subset_proof};
use crate::srs;
use crate::{elgamal, BLS12_381_SHARDS as N};

type F = <C as Pairing>::ScalarField;
type G1 = <C as Pairing>::G1Affine;

const RANGE_PROOF_POWERS: usize = fde::encrypt::elgamal::MAX_BITS * 4;

fn setup(range: usize) -> Powers<C> {
    let tau = F::rand(&mut test_rng());
    Powers::<C>::unsafe_setup(tau, range.max(RANGE_PROOF_POWERS))
}

fn random_file(len: usize) -> Vec<F> {
    let rng = &mut test_rng();
    (0..len).map(|_| F::rand(rng)).collect()
}

// ---------------------------------------------------------------- encoding

#[test]
fn encoding_is_a_systematic_reed_solomon_expansion() {
    // D_ell is a subgroup of D_m', so the file symbols must reappear inside the
    // codeword at stride m'/ell.  If that fails, `encode` is not the code the
    // protocol assumes and every downstream sample is meaningless.
    let file = random_file(64);
    let (_m, code_len) = code_lengths(file.len(), 3.38);
    let (encoded, _) = encode(&file, code_len);

    let stride = code_len / file.len();
    for (index, symbol) in file.iter().enumerate() {
        assert_eq!(encoded.codeword.evals[index * stride], *symbol);
    }
    assert_eq!(encoded.poly.degree(), file.len() - 1);
}

#[test]
fn encoding_without_expansion_is_the_identity() {
    let file = random_file(32);
    let (m, code_len) = code_lengths(file.len(), 1.0);
    assert_eq!((m, code_len), (32, 32));
    let (encoded, _) = encode(&file, code_len);
    assert_eq!(encoded.codeword.evals, file);
}

// ---------------------------------------------------------------- Lagrange

#[test]
fn barycentric_basis_reproduces_the_evaluation() {
    // The DLEQ proof is only sound if sum_i L_i(alpha) x_i == f_S(alpha) for the
    // *sampled* point set, which is not an FFT subgroup.
    let rng = &mut test_rng();
    let degree = 11usize;
    let points: Vec<F> = (0..=degree).map(|_| F::rand(rng)).collect();
    let poly = DensePolynomial::<F>::rand(degree, rng);
    let alpha = F::rand(rng);

    let basis = sample::lagrange_coefficients(&points, alpha);
    let combined: F = basis
        .iter()
        .zip(points.iter())
        .map(|(coefficient, point)| *coefficient * poly.evaluate(point))
        .sum();

    assert_eq!(combined, poly.evaluate(&alpha));
}

#[test]
fn sampling_is_deterministic_and_distinct() {
    let (first, _) = sample::sample_positions([7u8; 32], 256, 32);
    let (second, _) = sample::sample_positions([7u8; 32], 256, 32);
    let (other, _) = sample::sample_positions([8u8; 32], 256, 32);
    assert_eq!(first, second);
    assert_ne!(first, other);
    assert_eq!(first.len(), 32);
    assert!(first.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(first.iter().all(|&index| index < 256));
}

// ---------------------------------------------------------------- masking

#[test]
fn masking_round_trips_and_depends_on_the_key() {
    let data = random_file(64);
    let key = F::from(12345u64);
    let (cipher, _) = mask::mask_encrypt(&data, key);
    let (other, _) = mask::mask_encrypt(&data, key + F::from(1u64));

    assert_eq!(cipher.len(), data.len());
    assert!(cipher.iter().zip(&data).all(|(c, x)| c != x));
    assert_ne!(cipher, other);

    // Recovering the plaintext from the same key must give the file back.
    let (zeros, _) = mask::mask_encrypt(&vec![F::from(0u64); data.len()], key);
    let recovered: Vec<F> = cipher.iter().zip(&zeros).map(|(c, pad)| *c - pad).collect();
    assert_eq!(recovered, data);
}

// ------------------------------------------------------- subset KZG proof

struct Fixture {
    powers: Powers<C>,
    encoded: crate::encode::Encoded<F>,
    com_phi: <C as Pairing>::G1,
    positions: Vec<usize>,
    seed: [u8; 32],
}

fn fixture(ell: usize, r: usize, beta: f64) -> Fixture {
    let file = random_file(ell);
    let (m, code_len) = code_lengths(ell, beta);
    let (encoded, _) = encode(&file, code_len);
    let powers = setup(ell + 1);
    let com_phi = powers.commit_g1(&encoded.poly);
    let seed = sample::transcript_seed(&[com_phi.into_affine()]);
    let (positions, _) = sample::sample_positions(seed, m, r);
    Fixture {
        powers,
        encoded,
        com_phi,
        positions,
        seed,
    }
}

#[test]
fn subset_proof_verifies_blinded_and_plain() {
    let rng = &mut test_rng();
    for blind in [true, false] {
        let f = fixture(64, 8, 3.38);
        let proof =
            subset_proof::<C, _>(&f.powers, &f.encoded, &f.positions, &f.seed, blind, rng).unwrap();
        assert!(verify_subset_proof::<C>(&f.powers, f.com_phi, &proof));
        // Blinding must actually change the committed polynomial.
        assert_eq!(proof.subset_poly.degree() > f.positions.len(), blind);
    }
}

#[test]
fn subset_proof_rejects_a_tampered_quotient() {
    let rng = &mut test_rng();
    let f = fixture(64, 8, 3.38);
    let mut proof =
        subset_proof::<C, _>(&f.powers, &f.encoded, &f.positions, &f.seed, true, rng).unwrap();
    proof.com_quotient += <G1 as AffineRepr>::generator();
    assert!(!verify_subset_proof::<C>(&f.powers, f.com_phi, &proof));
}

#[test]
fn subset_proof_rejects_a_tampered_opening() {
    let rng = &mut test_rng();
    let f = fixture(64, 8, 3.38);
    let mut proof =
        subset_proof::<C, _>(&f.powers, &f.encoded, &f.positions, &f.seed, true, rng).unwrap();
    proof.opening = (proof.opening + <G1 as AffineRepr>::generator()).into_affine();
    assert!(!verify_subset_proof::<C>(&f.powers, f.com_phi, &proof));
}

#[test]
fn subset_proof_rejects_a_wrong_opened_value() {
    let rng = &mut test_rng();
    let f = fixture(64, 8, 3.38);
    let mut proof =
        subset_proof::<C, _>(&f.powers, &f.encoded, &f.positions, &f.seed, true, rng).unwrap();
    proof.value += F::from(1u64);
    assert!(!verify_subset_proof::<C>(&f.powers, f.com_phi, &proof));
}

#[test]
fn subset_proof_rejects_a_foreign_file_commitment() {
    let rng = &mut test_rng();
    let f = fixture(64, 8, 3.38);
    let proof =
        subset_proof::<C, _>(&f.powers, &f.encoded, &f.positions, &f.seed, true, rng).unwrap();
    let other = f.powers.commit_g1(&DensePolynomial::<F>::rand(63, rng));
    assert!(!verify_subset_proof::<C>(&f.powers, other, &proof));
}

#[test]
fn subset_proof_rejects_samples_that_do_not_lie_on_the_codeword() {
    // Interpolating positions the sender never committed to must break the
    // divisibility check, otherwise sampling would prove nothing.
    let rng = &mut test_rng();
    let f = fixture(64, 8, 3.38);
    let mut tampered = f.encoded;
    tampered.codeword.evals[f.positions[0]] += F::from(1u64);
    let proof =
        subset_proof::<C, _>(&f.powers, &tampered, &f.positions, &f.seed, true, rng).unwrap();
    assert!(!verify_subset_proof::<C>(&f.powers, f.com_phi, &proof));
}

// ---------------------------------------------------- ElGamal / DLEQ / range

fn veck_plus_fixture() -> (
    Fixture,
    elgamal::Ciphertexts<N, C>,
    crate::schemes::SubsetProof<C>,
    Vec<F>,
    fde::dleq::Proof<<C as Pairing>::G1, Keccak256>,
    <C as Pairing>::G1,
    F,
    G1,
) {
    let rng = &mut test_rng();
    let f = fixture(64, 8, 3.38);
    let sk = F::rand(rng);
    let pk = (<G1 as AffineRepr>::generator() * sk).into_affine();

    let proof =
        subset_proof::<C, _>(&f.powers, &f.encoded, &f.positions, &f.seed, false, rng).unwrap();
    let (ciphertexts, _) =
        elgamal::encrypt_positions::<N, C>(&f.encoded.codeword.evals, &f.positions, &pk);
    let points: Vec<F> = f
        .positions
        .iter()
        .map(|&index| f.encoded.code_domain.element(index))
        .collect();
    let lagrange = sample::lagrange_coefficients(&points, proof.alpha);
    let q_point: <C as Pairing>::G1 = Msm::msm_unchecked(&ciphertexts.random_points, &lagrange);
    let dleq = fde::dleq::Proof::<<C as Pairing>::G1, Keccak256>::new(
        &sk,
        q_point.into_affine(),
        <G1 as AffineRepr>::generator(),
        rng,
    );
    (f, ciphertexts, proof, lagrange, dleq, q_point, sk, pk)
}

#[test]
fn dleq_binds_the_ciphertexts_to_the_opening() {
    let (_f, ciphertexts, proof, lagrange, dleq, q_point, _sk, pk) = veck_plus_fixture();
    assert!(check_dleq::<N, C>(
        &dleq,
        &ciphertexts,
        &lagrange,
        proof.value,
        pk,
        q_point
    ));
}

#[test]
fn dleq_rejects_a_tampered_ciphertext() {
    let (_f, mut ciphertexts, proof, lagrange, dleq, q_point, _sk, pk) = veck_plus_fixture();
    ciphertexts.ciphers[0] = ciphertexts.ciphers[0] + ciphertexts.ciphers[1];
    assert!(!check_dleq::<N, C>(
        &dleq,
        &ciphertexts,
        &lagrange,
        proof.value,
        pk,
        q_point
    ));
}

#[test]
fn dleq_rejects_a_wrong_opened_value() {
    let (_f, ciphertexts, proof, lagrange, dleq, q_point, _sk, pk) = veck_plus_fixture();
    assert!(!check_dleq::<N, C>(
        &dleq,
        &ciphertexts,
        &lagrange,
        proof.value + F::from(1u64),
        pk,
        q_point
    ));
}

#[test]
fn split_scalars_detect_a_tampered_shard() {
    let (_f, mut ciphertexts, ..) = veck_plus_fixture();
    assert!(elgamal::verify_split_scalars(&ciphertexts));
    ciphertexts.short_ciphers[0][2] = ciphertexts.short_ciphers[0][1];
    assert!(!elgamal::verify_split_scalars(&ciphertexts));
}

#[test]
fn range_proofs_detect_a_tampered_proof() {
    let rng = &mut test_rng();
    let powers = setup(RANGE_PROOF_POWERS);
    let range_powers = srs::fde_prefix(&powers, RANGE_PROOF_POWERS);
    let values = random_file(4);

    let (mut proofs, _) = elgamal::prove_ranges::<N, C>(&values, &range_powers);
    assert!(elgamal::verify_ranges::<N, C>(&proofs, &range_powers));
    proofs[1][0].evaluations.g = F::rand(rng);
    assert!(!elgamal::verify_ranges::<N, C>(&proofs, &range_powers));
}

// ------------------------------------------------------------- extrapolation

#[test]
fn redundancy_matches_the_paper() {
    // beta_min = 3.37, 1.64, 1.26 at R = 256, 512, 1024 with lambda = 128 and a
    // 2^32 grinding budget; 2.41, 1.47, 1.20 without grinding.
    for (r, expected) in [(256usize, 3.37), (512, 1.64), (1024, 1.26)] {
        let beta = pfde_kzg::veck::compute_beta(r, 128 + 32);
        assert!((beta - expected).abs() < 0.02, "R={r}: {beta} vs {expected}");
    }
    for (r, expected) in [(256usize, 2.41), (512, 1.47), (1024, 1.20)] {
        let beta = pfde_kzg::veck::compute_beta(r, 128);
        assert!((beta - expected).abs() < 0.02, "R={r}: {beta} vs {expected}");
    }
}

#[test]
fn codeword_length_is_the_expansion_rounded_up() {
    for (ell, beta) in [(1024usize, 3.38), (4096, 1.26), (65536, 1.64)] {
        let (m, code_len) = code_lengths(ell, beta);
        assert_eq!(m, (ell as f64 * beta).ceil() as usize);
        assert!(code_len.is_power_of_two() && code_len >= m);
        assert!(code_len < 2 * m);
    }
}

#[test]
fn unused_import_guard() {
    // `FftField` is needed for `code_domain.element`, keep the import honest.
    let _ = <F as FftField>::GENERATOR;
}
