//! Powers-of-tau handling.
//!
//! The universal KZG SRS is shared by every scheme and every run, so it is
//! generated once and cached on disk.  Range proofs live in a different crate
//! (`fde`) with its own `Powers` type; since both are just `(Vec<G1>, Vec<G2>)`
//! we re-wrap a short prefix instead of generating a second SRS.

use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_std::test_rng;
use fde::commit::kzg::Powers as FdePowers;
use pfde_kzg::commit::kzg::Powers;
use pfde_kzg::commit::powers_cache::PowersCache;
use std::path::Path;
use std::time::{Duration, Instant};

/// Load (creating if necessary) the first `range` powers of tau for `C`.
pub fn load<C: Pairing>(
    dir: &Path,
    chunk_size: usize,
    range: usize,
) -> Result<(Powers<C>, Duration), String> {
    let started = Instant::now();
    let mut cache = if dir.join("manifest.txt").exists() {
        PowersCache::<C>::open(dir).map_err(|err| err.to_string())?
    } else {
        let tau = C::ScalarField::rand(&mut test_rng());
        PowersCache::<C>::open_or_create(dir, tau, chunk_size).map_err(|err| err.to_string())?
    };
    cache.ensure_range(range).map_err(|err| err.to_string())?;
    let powers = cache.load_prefix(range).map_err(|err| err.to_string())?;
    Ok((powers, started.elapsed()))
}

/// A short prefix of the same SRS, in the shape the vendored `fde` crate wants.
pub fn fde_prefix<C: Pairing>(powers: &Powers<C>, range: usize) -> FdePowers<C> {
    let range = range.min(powers.g1.len());
    FdePowers {
        g1: powers.g1[..range].to_vec(),
        g2: powers.g2[..range].to_vec(),
    }
}
