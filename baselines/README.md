# Baselines

Vendored copies of the reference implementations we compare against, so that the
whole evaluation can be reproduced from a single clone.  Nothing here is our
work; the licences and attributions of the originals apply.

| Directory          | Upstream | Used for |
| ------------------ | -------- | -------- |
| `fde/`             | [PopcornPaws/fde](https://github.com/PopcornPaws/fde) — Tas, Nikolaenko, Seres, Melczer, Zhang, Kelkar, Bonneau, *Atomic BlockChain Data Exchange with Fairness* ([ePrint 2024/418](https://eprint.iacr.org/2024/418)) | exponential ElGamal, the shard range proofs, DLEQ proofs, and the KZG helpers used by VECK\_EL and VECK+\_EL |
| `veck-star-snark/` | the Go/gnark circuit shipped with VECK\*\_EL (arXiv:2506.14944) | the Groth16 circuit of VECK\*\_EL on BW6-761 with native BLS12-377 G1 arithmetic |

## Changes to `fde/`

1. **Real random sampling and a real division.**  Upstream selects the "random"
   subset as an FFT *subdomain*, which lets it divide by the vanishing polynomial
   with `divide_by_vanishing_poly` in O(n).  A genuinely random subset has an
   arbitrary vanishing polynomial, so we added `src/veck/kzg/elgamal/divide.rs`
   (Newton-inversion Euclidean division with a blocked path for low-degree
   divisors) and use it instead.  Without this the baseline gets a division
   speed-up that the protocol does not actually admit, which would flatter it
   relative to our scheme.
2. **Trimmed.**  `benches/` (Criterion harnesses that need a checked-in
   `powers.bin`) and `contracts/` (the Solidity settlement layer) were removed,
   together with the corresponding `[[bench]]` entries and the `criterion`
   dev-dependency.  The library sources are otherwise unmodified.
3. `src/commit/powers_cache.rs` was added so that the powers of tau can be
   generated once and shared with our own crates rather than regenerated per run.

Note that `fde/src/veck/kzg/elgamal/divide.rs` is *not* on the measured path:
the harness routes every scheme's `(phi - f_S) / Z_S` through
`PFDE-KZG`'s `subset_quotient_with_vanishing_poly`, so all four schemes get
exactly the same division code and the same dispatch threshold.  The file is kept
so the vendored crate still builds and its own tests still run.

The orchestration of the baseline protocols — which stage runs when, and what is
timed — lives in `benchmarks/kzg`, not here.  That code drives the primitives
above directly instead of calling upstream's `Proof::new_v2`, because upstream's
prover and verifier assume the FFT-subdomain sampling described in point 1 and no
longer verify once real sampling is used.  Every scheme in the harness runs its
verifier and asserts that it accepts, so the reconstructed baselines are complete
protocol runs, not proving-only skeletons.

## Changes to `veck-star-snark/`

Only the benchmark plumbing: `const N` moved into build-tag-selected
`params_r*.go` files, `bench.go` added for CSV output, and `main` now honours
`runtime.NumCPU()` instead of a hard-coded `GOMAXPROCS(32)`.  The circuit itself
is untouched.
