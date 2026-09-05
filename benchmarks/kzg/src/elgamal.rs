//! Exponential ElGamal encryption and range proofs, as used by VECK and VECK+.
//!
//! Both schemes split every scalar into `N` 32-bit shards so that the buyer can
//! brute-force the discrete logarithms, encrypt each shard, and (VECK for the
//! whole file, VECK+ for the sampled positions) attach a range proof per shard.
//!
//! Full-file encryption at `ell = 2^20` produces tens of gigabytes of group
//! elements, which no sender would ever buffer.  `encrypt_streaming` therefore
//! performs exactly the same work but retains only the positions the proof
//! actually needs, which is what a streaming implementation would do.

use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_std::rand::Rng;
use ark_std::Zero;
use fde::commit::kzg::Powers as FdePowers;
use fde::encrypt::elgamal::{Cipher, ExponentialElgamal, SplitScalar, MAX_BITS};
use fde::encrypt::EncryptionEngine;
use fde::range_proof::RangeProof;
use rayon::prelude::*;
use sha3::Keccak256;

pub type Elgamal<C> = ExponentialElgamal<<C as Pairing>::G1>;

/// The ElGamal material the prover keeps for a set of positions.
pub struct Ciphertexts<const N: usize, C: Pairing> {
    /// `c = (g^r, g^x h^r)` for the plaintext itself.
    pub ciphers: Vec<Cipher<C::G1>>,
    /// The `N` shard ciphertexts whose homomorphic sum reproduces `ciphers`.
    pub short_ciphers: Vec<[Cipher<C::G1>; N]>,
    /// `g^r`, needed by the DLEQ proof.
    pub random_points: Vec<C::G1Affine>,
}

fn encrypt_one<const N: usize, C: Pairing, R: Rng>(
    value: C::ScalarField,
    encryption_pk: &C::G1Affine,
    rng: &mut R,
) -> (Cipher<C::G1>, [Cipher<C::G1>; N], C::G1Affine) {
    let split = SplitScalar::<N, C::ScalarField>::from(value);
    let (short_ciphers, randomness) = split.encrypt::<Elgamal<C>, _>(encryption_pk, rng);
    let cipher = <Elgamal<C> as EncryptionEngine>::encrypt_with_randomness(
        &value,
        encryption_pk,
        &randomness,
    );
    let random_point = (<C::G1Affine as AffineRepr>::generator() * randomness).into_affine();
    (cipher, short_ciphers, random_point)
}

/// Encrypt every symbol, keep nothing.  Returns the elapsed time only; the
/// returned `usize` exists to stop the optimiser from eliding the work.
pub fn encrypt_streaming<const N: usize, C: Pairing>(
    data: &[C::ScalarField],
    encryption_pk: &C::G1Affine,
) -> usize {
    data
        .par_iter()
        .map(|value| {
            let rng = &mut ark_std::rand::thread_rng();
            let (cipher, short, point) = encrypt_one::<N, C, _>(*value, encryption_pk, rng);
            usize::from(cipher.c0().is_zero())
                + usize::from(short[0].c0().is_zero())
                + usize::from(point.is_zero())
        })
        .sum()
}

/// Encrypt the given positions and keep the ciphertexts.
pub fn encrypt_positions<const N: usize, C: Pairing>(
    data: &[C::ScalarField],
    positions: &[usize],
    encryption_pk: &C::G1Affine,
) -> Ciphertexts<N, C> {
    let triples: Vec<_> = positions
        .par_iter()
        .map(|&index| {
            let rng = &mut ark_std::rand::thread_rng();
            encrypt_one::<N, C, _>(data[index], encryption_pk, rng)
        })
        .collect();

    let mut ciphers = Vec::with_capacity(triples.len());
    let mut short_ciphers = Vec::with_capacity(triples.len());
    let mut random_points = Vec::with_capacity(triples.len());
    for (cipher, short, point) in triples {
        ciphers.push(cipher);
        short_ciphers.push(short);
        random_points.push(point);
    }

    Ciphertexts {
        ciphers,
        short_ciphers,
        random_points,
    }
}

/// One ElGamal ciphertext per position, with no shard decomposition.
///
/// The 32-bit split above exists so the buyer can brute-force the discrete
/// logarithm of each piece.  VECK*'s sampled ciphertexts are never decrypted
/// that way -- they are inputs to its SNARK, which proves the encryption
/// relation itself -- so it needs one ciphertext per sample, not `N + 1`.
pub fn encrypt_positions_plain<C: Pairing>(
    data: &[C::ScalarField],
    positions: &[usize],
    encryption_pk: &C::G1Affine,
) -> Vec<Cipher<C::G1>> {
    positions
        .par_iter()
        .map(|&index| {
            let rng = &mut ark_std::rand::thread_rng();
            <Elgamal<C> as EncryptionEngine>::encrypt(&data[index], encryption_pk, rng)
        })
        .collect()
}

/// Range-prove every shard of every listed value.
pub fn prove_ranges<const N: usize, C: Pairing>(
    values: &[C::ScalarField],
    powers: &FdePowers<C>,
) -> Vec<[RangeProof<C, Keccak256>; N]> {
    values
        .par_iter()
        .map(|value| {
            let rng = &mut ark_std::rand::thread_rng();
            let split = SplitScalar::<N, C::ScalarField>::from(*value);
            split
                .splits()
                .clone()
                .map(|shard| {
                    RangeProof::<C, Keccak256>::new(shard, MAX_BITS, powers, rng)
                        .expect("range proof input out of range")
                })
        })
        .collect()
}

/// Range-prove `count` values without keeping the proofs (used when the full
/// file is range-proved and buffering all of it is impossible).
pub fn prove_ranges_streaming<const N: usize, C: Pairing>(
    values: &[C::ScalarField],
    powers: &FdePowers<C>,
) -> usize {
    values
        .par_iter()
        .map(|value| {
            let rng = &mut ark_std::rand::thread_rng();
            let split = SplitScalar::<N, C::ScalarField>::from(*value);
            split
                .splits()
                .iter()
                .map(|shard| {
                    let proof = RangeProof::<C, Keccak256>::new(*shard, MAX_BITS, powers, rng)
                        .expect("range proof input out of range");
                    usize::from(proof.evaluations.g.is_zero())
                })
                .sum::<usize>()
        })
        .sum()
}

/// Verify that the shard ciphertexts sum back to the plaintext ciphertext.
pub fn verify_split_scalars<const N: usize, C: Pairing>(ciphertexts: &Ciphertexts<N, C>) -> bool {
    ciphertexts
        .ciphers
        .par_iter()
        .zip(ciphertexts.short_ciphers.par_iter())
        .all(|(cipher, short)| cipher.check_encrypted_sum(short))
}

/// Verify a batch of range proofs.
pub fn verify_ranges<const N: usize, C: Pairing>(
    proofs: &[[RangeProof<C, Keccak256>; N]],
    powers: &FdePowers<C>,
) -> bool {
    proofs
        .par_iter()
        .all(|group| group.iter().all(|proof| proof.verify(MAX_BITS, powers).is_ok()))
}
