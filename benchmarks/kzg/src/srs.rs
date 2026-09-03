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

/// G2 capacity a freshly created cache is given, whatever the current run asks
/// for.  The cache's G2 budget is fixed at creation, so sizing it to one run's
/// `R` would make the next run with a larger `R` fail; 4096 points cost under a
/// megabyte and cover every sample count anyone would use.
const DEFAULT_G2_CAPACITY: usize = 1 << 12;

/// Load (creating if necessary) `g1_range` G1 powers and `g2_range` G2 powers.
///
/// G2 is only touched by the verifier — `commit_g2` of the sampled vanishing
/// polynomial (degree `R`) and `g2_tau` — so `g2_range` is `O(R)`, not
/// `O(ell)`.  On BLS12-381 a G2 point is 192 bytes against G1's 96, so capping
/// it removes about two thirds of the SRS in both time and space.
pub fn load<C: Pairing>(
    dir: &Path,
    chunk_size: usize,
    g1_range: usize,
    g2_range: usize,
) -> Result<(Powers<C>, Duration), String> {
    let started = Instant::now();
    let mut cache = if dir.join("manifest.txt").exists() {
        PowersCache::<C>::open(dir).map_err(|err| err.to_string())?
    } else {
        let tau = C::ScalarField::rand(&mut test_rng());
        let capacity = g2_range.max(DEFAULT_G2_CAPACITY);
        PowersCache::<C>::open_or_create(dir, tau, chunk_size, capacity)
            .map_err(|err| err.to_string())?
    };
    if cache.manifest().g2_range < g2_range {
        return Err(format!(
            "the cache in {} holds {} G2 powers but this run needs {}; delete it or point \
             --srs-dir somewhere else",
            dir.display(),
            cache.manifest().g2_range,
            g2_range,
        ));
    }
    cache.ensure_range(g1_range).map_err(|err| err.to_string())?;
    let powers = cache
        .load_prefix_with_g2(g1_range, g2_range)
        .map_err(|err| err.to_string())?;
    Ok((powers, started.elapsed()))
}

/// A short prefix of the same SRS, in the shape the vendored `fde` crate wants.
pub fn fde_prefix<C: Pairing>(powers: &Powers<C>, range: usize) -> FdePowers<C> {
    FdePowers {
        g1: powers.g1[..range.min(powers.g1.len())].to_vec(),
        g2: powers.g2[..range.min(powers.g2.len())].to_vec(),
    }
}
