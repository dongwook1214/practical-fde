//! Symmetric masking of the codeword.
//!
//! VECK* and our construction do not public-key-encrypt the payload: the sender
//! transmits `ct_i = x_i + PRF(sk, i)` for every codeword symbol and later
//! reveals `sk`.  In the circuits this PRF is Poseidon2 over a width-2 state,
//! 8 full and 50 partial rounds (`NewPoseidon2FromParameters(api, 2, 8, 50)`),
//! one permutation per symbol.
//!
//! Here we run a Poseidon permutation with the *same* width and round counts,
//! written out directly instead of going through `PoseidonSponge`.  That matters:
//! the sponge allocates on every absorb and squeeze and, at its default width 3,
//! does 9 multiplications per linear layer instead of 4.  At `m = 3.5M` symbols
//! the difference is minutes, and masking is the dominant stage of our own
//! scheme — measuring library overhead instead of the primitive would inflate
//! exactly the number the paper reports.
//!
//! Round constants come from the same Grain LFSR arkworks uses, so this is a
//! standard Poseidon instance; Poseidon2 differs only in the linear layer, which
//! at width 2 is a 2x2 matrix either way.

use ark_crypto_primitives::sponge::poseidon::find_poseidon_ark_and_mds;
use ark_ff::PrimeField;
use rayon::prelude::*;

const RATE: usize = 1;
const CAPACITY: usize = 1;
const WIDTH: usize = RATE + CAPACITY;
const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 50;

/// A width-2 Poseidon permutation with an `x^5` S-box.
pub struct Prf<F: PrimeField> {
    ark: Vec<[F; WIDTH]>,
    mds: [[F; WIDTH]; WIDTH],
}

impl<F: PrimeField> Prf<F> {
    pub fn new() -> Self {
        let (ark, mds) = find_poseidon_ark_and_mds::<F>(
            F::MODULUS_BIT_SIZE as u64,
            RATE,
            FULL_ROUNDS as u64,
            PARTIAL_ROUNDS as u64,
            0,
        );
        Self {
            ark: ark
                .into_iter()
                .map(|round| [round[0], round[1]])
                .collect(),
            mds: [[mds[0][0], mds[0][1]], [mds[1][0], mds[1][1]]],
        }
    }

    #[inline(always)]
    fn sbox(value: F) -> F {
        let square = value * value;
        square * square * value
    }

    #[inline(always)]
    fn linear(&self, state: &mut [F; WIDTH]) {
        let (a, b) = (state[0], state[1]);
        state[0] = self.mds[0][0] * a + self.mds[0][1] * b;
        state[1] = self.mds[1][0] * a + self.mds[1][1] * b;
    }

    /// `PRF(key, index)`, one permutation, no allocation.
    #[inline]
    pub fn eval(&self, key: F, index: u64) -> F {
        let mut state = [F::from(index), key];
        let half = FULL_ROUNDS / 2;

        for round in 0..half {
            state[0] += self.ark[round][0];
            state[1] += self.ark[round][1];
            state[0] = Self::sbox(state[0]);
            state[1] = Self::sbox(state[1]);
            self.linear(&mut state);
        }
        for round in half..half + PARTIAL_ROUNDS {
            state[0] += self.ark[round][0];
            state[1] += self.ark[round][1];
            state[0] = Self::sbox(state[0]);
            self.linear(&mut state);
        }
        for round in half + PARTIAL_ROUNDS..FULL_ROUNDS + PARTIAL_ROUNDS {
            state[0] += self.ark[round][0];
            state[1] += self.ark[round][1];
            state[0] = Self::sbox(state[0]);
            state[1] = Self::sbox(state[1]);
            self.linear(&mut state);
        }

        state[0]
    }
}

impl<F: PrimeField> Default for Prf<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// Encrypt the whole codeword with the PRF mask.  Round constants are public
/// parameters, so `Prf::new` belongs outside the caller's timed region.
pub fn mask_encrypt<F: PrimeField>(prf: &Prf<F>, codeword: &[F], key: F) -> Vec<F> {
    codeword
        .par_iter()
        .enumerate()
        .map(|(index, symbol)| *symbol + prf.eval(key, index as u64))
        .collect()
}
