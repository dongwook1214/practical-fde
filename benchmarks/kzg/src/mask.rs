//! Symmetric masking of the codeword.
//!
//! VECK* and our construction do not public-key-encrypt the payload: the sender
//! transmits `ct_i = x_i + PRF(sk, i)` for every codeword symbol and later
//! reveals `sk`.  The in-circuit hash is Poseidon2 (gnark); on the host side we
//! use the arkworks Poseidon sponge with the same S-box and comparable round
//! numbers as a stand-in.  Poseidon2 has a strictly cheaper linear layer, so
//! this is a conservative estimate of the masking cost, and it is charged
//! identically to VECK* and to us.

use ark_crypto_primitives::sponge::poseidon::{
    find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge,
};
use ark_crypto_primitives::sponge::{
    Absorb, CryptographicSponge, DuplexSpongeMode, FieldBasedCryptographicSponge,
};
use ark_ff::PrimeField;
use rayon::prelude::*;
use std::time::{Duration, Instant};

const RATE: usize = 2;
const CAPACITY: usize = 1;
const FULL_ROUNDS: u64 = 8;
const PARTIAL_ROUNDS: u64 = 57;
const ALPHA: u64 = 5;

/// Poseidon over `F` with state width 3 (rate 2, capacity 1) and an `x^5` S-box.
pub fn poseidon_config<F: PrimeField>() -> PoseidonConfig<F> {
    let (ark, mds) = find_poseidon_ark_and_mds::<F>(
        F::MODULUS_BIT_SIZE as u64,
        RATE,
        FULL_ROUNDS,
        PARTIAL_ROUNDS,
        0,
    );
    PoseidonConfig::new(
        FULL_ROUNDS as usize,
        PARTIAL_ROUNDS as usize,
        ALPHA,
        mds,
        ark,
        RATE,
        CAPACITY,
    )
}

fn prf<F: PrimeField + Absorb>(sponge: &mut PoseidonSponge<F>, key: F, index: u64) -> F {
    for slot in sponge.state.iter_mut() {
        *slot = F::zero();
    }
    sponge.mode = DuplexSpongeMode::Absorbing {
        next_absorb_index: 0,
    };
    sponge.absorb(&key);
    sponge.absorb(&F::from(index));
    sponge.squeeze_native_field_elements(1)[0]
}

/// Encrypt the whole codeword with the PRF mask; returns the ciphertext and the
/// time spent.
pub fn mask_encrypt<F: PrimeField + Absorb>(codeword: &[F], key: F) -> (Vec<F>, Duration) {
    // Round constants are part of the public parameters, not of the online cost.
    let config = poseidon_config::<F>();
    let started = Instant::now();
    let cipher: Vec<F> = codeword
        .par_iter()
        .enumerate()
        .map_init(
            || PoseidonSponge::<F>::new(&config),
            |sponge, (index, symbol)| *symbol + prf(sponge, key, index as u64),
        )
        .collect();
    (cipher, started.elapsed())
}
