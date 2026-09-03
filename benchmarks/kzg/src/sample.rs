//! Fiat--Shamir sampling of the `R` codeword positions the buyer will check.

use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::{Rng, SeedableRng};
use sha3::{Digest, Keccak256};
use std::collections::HashSet;

/// Hash a transcript into a seed.
pub fn transcript_seed<T: CanonicalSerialize>(items: &[T]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    let mut bytes = Vec::new();
    for item in items {
        bytes.clear();
        item.serialize_compressed(&mut bytes)
            .expect("serialisation should not fail");
        hasher.update(&bytes);
    }
    hasher.finalize().into()
}

/// Derive `count` distinct positions in `0..len` from `seed`.
pub fn sample_positions(seed: [u8; 32], len: usize, count: usize) -> Vec<usize> {
    assert!(count <= len, "cannot sample more positions than the codeword has");
    let mut rng = StdRng::from_seed(seed);
    let mut chosen = HashSet::with_capacity(count);
    while chosen.len() < count {
        chosen.insert(rng.gen_range(0..len));
    }
    let mut positions: Vec<usize> = chosen.into_iter().collect();
    positions.sort_unstable();
    positions
}

/// Derive the evaluation point `alpha` from a transcript.
pub fn challenge_scalar<F: PrimeField>(seed: &[u8; 32], label: &[u8]) -> F {
    let mut hasher = Keccak256::new();
    hasher.update(seed);
    hasher.update(label);
    F::from_le_bytes_mod_order(&hasher.finalize())
}

/// Barycentric Lagrange basis of the sampled point set, evaluated at `alpha`.
///
/// The sampled positions are an arbitrary subset of the codeword domain, not a
/// subgroup, so the FFT shortcut used by the reference implementations does not
/// apply and we evaluate the basis directly, exactly as the SNARK host code does.
pub fn lagrange_coefficients<F: PrimeField>(points: &[F], alpha: F) -> Vec<F> {
    let n = points.len();
    let mut weights = vec![F::one(); n];
    let mut alpha_diffs = vec![F::zero(); n];

    for i in 0..n {
        alpha_diffs[i] = alpha - points[i];
        let mut acc = F::one();
        for j in 0..n {
            if i != j {
                acc *= points[i] - points[j];
            }
        }
        weights[i] = acc;
    }

    // w_i = 1 / prod_{j != i} (x_i - x_j), and 1 / (alpha - x_i).
    ark_ff::batch_inversion(&mut weights);
    ark_ff::batch_inversion(&mut alpha_diffs);

    let mut scaled = vec![F::zero(); n];
    let mut sum = F::zero();
    for i in 0..n {
        scaled[i] = weights[i] * alpha_diffs[i];
        sum += scaled[i];
    }

    let sum_inv = sum
        .inverse()
        .expect("barycentric denominator must be non-zero");
    scaled.iter().map(|value| *value * sum_inv).collect()
}
