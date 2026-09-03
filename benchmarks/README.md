# End-to-end benchmark

Everything the *sender* has to do to sell a file of `ell` field elements, for the
four schemes compared in the paper, on both curves, for `ell` from `2^10` to
`2^20`.

Earlier revisions of the paper compared only proof generation against
VECK\*\_EL.  This harness widens that to the whole sender path — Reed–Solomon
encoding, encryption, the KZG proof and the SNARK — and adds VECK\_EL and
VECK+\_EL to the comparison.

## What is measured

Every scheme is expressed as the same sequence of stages, so the CSV columns line
up across schemes:

| stage | meaning |
| ----- | ------- |
| `encode` | Reed–Solomon expansion `ell -> m = ceil(beta * ell)`.  The file lives on the subgroup `D_ell`, the codeword on `D_m'` with `m' = 2^ceil(log2 m)`; since `D_ell <= D_m'` the code is systematic and both halves are FFTs (`Evaluations::interpolate` and `evaluate_over_domain`).  For base VECK, which does not code, only the interpolation runs. |
| `commit` | the KZG commitment `C_phi` to the degree-`(ell-1)` message polynomial. |
| `encrypt` | whatever the sender applies to **every** transmitted symbol: exponential ElGamal for VECK and VECK+, a Poseidon PRF mask for VECK\* and for us. |
| `sample` | Fiat–Shamir derivation of the `R` checked positions. |
| `subset` | interpolation of the sampled polynomial `f_S` and its commitment. |
| `sample_crypto` | per-sample public-key work: range proofs for VECK+, the in-circuit ElGamal ciphertexts for VECK\*, nothing for us.  For base VECK this is the range proofs over the *whole* file. |
| `kzg_proof` | quotient, its commitment, the opening at `alpha`, and (VECK, VECK+) the DLEQ proof. |
| `verify` | the buyer's checks — run and asserted, never assumed. |

The Groth16 part of VECK\* and of our scheme is measured separately by the Go
drivers and joined in by `scripts/aggregate.py`, because it depends only on `R`,
never on the file size.

## Which scheme runs on which curve

| scheme | BLS12-381 | BW6-761 |
| ------ | --------- | ------- |
| VECK\_EL | yes | — |
| VECK+\_EL | yes | — |
| VECK\*\_EL | — | yes (its in-circuit ElGamal shares the KZG group, forcing a 2-chain) |
| ours | yes | yes |

The harness refuses the undefined combinations rather than silently producing a
number for them.

## Redundancy

`beta` comes from `compute_beta(R, lambda + grinding)` with `lambda = 128` and
`grinding = 32`, i.e. the grinding-aware condition
`q_S ((beta+1)/2beta)^R <= 2^-128` with `q_S = 2^32`.  That reproduces the
paper's `beta = 3.38, 1.64, 1.26` at `R = 256, 512, 1024`.  Pass `--grinding 0`
for the no-grinding numbers (`2.42, 1.47, 1.20`).

## Running it

```bash
./benchmarks/scripts/run_all.sh              # everything, then aggregate + plot
SKIP_SNARK=1 ./benchmarks/scripts/run_all.sh # Rust side only
MAX_LOG=14 ./benchmarks/scripts/run_all.sh   # a quick pass
```

Single runs:

```bash
cd benchmarks/kzg
cargo run --release -- --scheme ours --curve bls12-381 --min-log 10 --max-log 20 \
    --subsets 256,512,1024 --out ../results/kzg_ours_bls12-381.csv

cd PFDE-SNARK/bls12-381 && go run -tags r512 . -csv ../../benchmarks/results/snark.csv
```

The Go drivers take `-cores` (default `runtime.NumCPU()`), and the value is
recorded in `snark.csv`.  This matters for the baseline: the reference VECK*
driver hard-coded `GOMAXPROCS(32)` while ours used `runtime.NumCPU()`, so the two
were never on the same budget.  Both now default to the machine's core count;
pass `-cores 32` to reproduce the older VECK* figure.

`--help` lists every option.  The powers of tau are generated once into
`benchmarks/kzg/.cache/srs/<curve>/` and reused.

## The SRS is asymmetric on purpose

G2 powers are only touched by the verifier: `commit_g2` of the sampled vanishing
polynomial (degree `R`) and `g2_tau` for the opening check.  Nothing needs
`O(ell)` of them.  The cache therefore takes a separate `g2_range = R + 2`, and
since a compressed BLS12-381 G2 point is 192 bytes against G1's 96, that removes
two thirds of the SRS in time, disk and resident memory:

| `ell = 2^17`, BLS12-381 | full G2 | `g2_range = 1026` |
| --- | --- | --- |
| generation | 120.8 s | **31.7 s** |
| on disk | 36.0 MiB | **12.2 MiB** |

The ratio is the same at every size, so at `ell = 2^20` the SRS is about 100 MiB
rather than 300 MiB.  `PFDE-KZG`'s own CLI takes the same budget:

```bash
cd PFDE-KZG/bls12-381
cargo run --release -- setup-cache --range 1048577 --g2-range 4096
```

A cache whose curve, chunk size, tau or `g2_range` does not match what a run
needs is refused with a message saying which, rather than being quietly
reinterpreted.  The cache is derived data with no format compatibility to
maintain: if anything about it looks wrong, delete the directory and let it
regenerate.

## Extrapolation

Two stages touch every transmitted symbol with public-key operations:

* base VECK range-proves all `8 * ell` 32-bit shards of the file, and
* VECK+ ElGamal-encrypts the whole `m`-symbol codeword.

At `ell = 2^20` those cost days and hours respectively.  Both are exactly linear
in the number of symbols and embarrassingly parallel, so by default the harness
measures them once on a bounded prefix (`--max-measured-log`, default 14 for VECK
and 16 for VECK+) and scales the per-symbol cost.  Rows produced this way carry
`extrapolated=true` and are drawn dashed in the figure.  `--no-extrapolate`
measures everything, at the cost of a multi-day run.

The linearity assumption is checkable, and worth checking on your own machine:

```bash
for cap in 10 11 12; do
  ./target/release/pfde-bench --scheme veck-plus --curve bls12-381 \
      --min-log 14 --max-log 14 --subsets 256 --max-measured-log $cap \
      --no-verify --out /tmp/lin_$cap.csv
done   # compare encrypt_ms/m across the three
```

On the reference run the per-symbol cost moved by 4.5% across a 4x change in the
prefix, and by 0.6% between the two largest prefixes — the residual is parallel
warm-up, and it shrinks as the prefix grows.

Nothing else is extrapolated: encoding, commitment, the masking of the codeword,
sampling, the subset polynomial, the quotient and every opening are measured at
the full file size for every row.  VECK+ rows still verify when extrapolated,
because only the whole-codeword encryption *timing* is scaled — the sampled
ciphertexts, range proofs and DLEQ are real.  VECK rows do not: there the buyer
receives the whole file, so with nothing materialised there is nothing to check.

## Outputs

```
benchmarks/results/
  kzg_<scheme>_<curve>.csv     per-stage timings from the Rust driver
  snark.csv                    Groth16 + CP-link timings from the Go drivers
  end_to_end.csv               the join, with total sender and verifier times
  pgfplots/proving_time.tex    \addplot blocks to paste into main.tex
  pgfplots/snark_table.tex     rows for the SNARK resource table
  figures/end_to_end.{pdf,png} preview figure
```

## Tests

```bash
cd benchmarks/kzg && cargo test --release
```

19 tests, and the ones that matter are the negative ones: an `assert!(verified)`
inside a benchmark means nothing unless the same verifier also rejects.  The
suite tampers with the quotient commitment, the opening, the opened value, the
file commitment, a sampled codeword symbol, an ElGamal ciphertext, a shard
ciphertext and a range proof, and requires each to be rejected.  It also checks
that the encoding really is systematic (file symbols reappear in the codeword at
stride `m'/ell`), that the barycentric Lagrange basis reproduces `f(alpha)` on a
non-subgroup point set — the DLEQ is unsound otherwise — and that `beta`
reproduces the paper's `3.37 / 1.64 / 1.26` and `2.41 / 1.47 / 1.20`.

`PFDE-KZG` has its own suite (`cd PFDE-KZG/bls12-381 && cargo test --release`),
including `divide::test::both_strategies_agree`, which requires the two division
strategies to return identical quotients *and* remainders for divisor degrees 64
through 2048 — the dispatch threshold must only change the cost, never the answer.

The Go drivers are covered by `go vet` rather than tests; run it after any edit.

## What each scheme's row contains

A blank cell is *structurally* zero — the scheme has no such step — not an
omission.  `--` means the stage does not exist for that scheme.

| stage | VECK | VECK+ | VECK* | ours |
| --- | --- | --- | --- | --- |
| `encode` | interpolate `phi` only (`beta = 1`, no expansion) | interpolate + expand to `m` | interpolate + expand to `m` | interpolate + expand to `m` |
| `commit` | `C_phi` | `C_phi` | `C_phi` | `C_phi` |
| `encrypt` | ElGamal of all `ell` symbols (8 shards + 1 full each) | ElGamal of all `m` codeword symbols | Poseidon mask of all `m` symbols | Poseidon mask of all `m` symbols |
| `sample` | -- | `R` positions of `m` | `R` positions of `m` | `R` positions of `m` |
| `subset` | -- | interpolate `f_S`, commit (**unblinded**) | interpolate `f_S` + blinder, commit | interpolate `f_S` + blinder, commit |
| `sample_crypto` | range proofs for all `8*ell` shards | range proofs for the `8R` sampled shards | ElGamal of the `R` sampled symbols | -- (this is the contribution) |
| `kzg_proof` | open `phi` at `alpha`, DLEQ over `ell` ciphertexts | quotient, commit, open `f_S`, DLEQ over `R` | quotient, commit, open `f_S` | quotient, commit, open `f_S`, `U_alpha` |
| SNARK (Go) | -- | -- | Groth16 prove | Groth16 prove + CP-link prove |
| `verify` | opening, DLEQ, shard sums, all range proofs | subset pairing, opening, DLEQ, shard sums, `R` range proofs | subset pairing, opening, shard sums, Groth16 verify | subset pairing, opening, Groth16 verify, CP-link verify |

## What no row contains

Excluded from every scheme, so the comparison is like-for-like:

* **SRS generation and load.**  Reported separately as `srs_load_ms`; never in
  `prove_total_ms`.
* **Groth16 setup, circuit compilation and CRS serialisation.**  Reported by the
  Go driver as `setup_ms` / `compile_ms` / `crs_bytes`; one-time per circuit, so
  outside the online total.  CP-link setup likewise.
* **Transcript hashing.**  `sample_ms` times only the derivation of the `R`
  indices from a seed; hashing the `m` ciphertexts that produce that seed is not
  timed.  This is `O(m)` work that VECK+, VECK* and we would all pay.
* **The buyer's decryption.**  For VECK and VECK+ this means brute-forcing a
  32-bit discrete log per shard — `8*ell` of them for VECK — which is a
  substantial real cost that appears nowhere in these numbers.  For VECK* and for
  us the buyer just subtracts the PRF stream.
* **Reed--Solomon decoding**, serialisation, network transfer, peak memory, and
  the settlement contract (adaptor signature, on-chain `Ver_key`).
* **`C_phi` is charged to every sale.**  In a deployment the file commitment is
  published once and amortised over all buyers; it is in `prove_total_ms` for all
  four schemes equally.

Per-scheme details worth stating in a paper:

* **VECK** is extrapolated above `ell = 2^14`: its encryption, range proofs and
  the two size-`ell` DLEQ multi-scalar multiplications are scaled from a measured
  prefix, and those rows are not verified because no ciphertexts are
  materialised.  In extrapolated rows the DLEQ MSM is timed over SRS points
  rather than real ciphertexts, which costs the same for the same number of bases.
* **VECK+** is extrapolated above `ell = 2^16`, but only its whole-codeword
  ElGamal: the sampled ciphertexts, range proofs, DLEQ and KZG work are real, and
  those rows still verify.  The re-encryption of the `R` sampled positions is
  performed but deliberately not timed — a streaming prover keeps them from the
  first pass; charging it twice would inflate VECK+.
* **VECK\*** is charged the same whole-codeword Poseidon mask as we are.  The
  reference implementation does not benchmark that stage at all, so this is an
  addition on its behalf, using our PRF rather than its MiMC.  Its KZG group is
  instantiated as BW6-761 rather than its inner BLS12-377.
* **The SNARK circuits are untouched.**  `Circuit`, `Define` and the range checks
  are byte-identical to the sources this repository started from, in all three
  drivers, so the constraint counts are the originals.  The only edits are
  benchmark plumbing: `const N` moved into build-tag-selected `params_r*.go`
  files, the durations that were already being printed are also stored in a
  `metrics` struct, `main` parses flags and appends a CSV row, and `-cores`
  replaces the hard-coded `GOMAXPROCS`.
* **Ours** double-counts `R` symbols of masking: the Go driver recomputes
  Poseidon2 for the `R` circuit inputs on the host.  With `R <= 1024` against
  `m >= 1290` this is under a thousandth of the stage and is left alone rather
  than special-cased.

## Cross-check against the published table

The reconstructed VECK+ verifier reproduces the paper's own
`tab:SNARK-verification-time` on the same machine, which is the strongest
available evidence that the reconstruction is faithful rather than merely
self-consistent:

| R | paper | this harness |
| --- | --- | --- |
| 256 | 1171 ms | 1179 ms |
| 512 | 2353 ms | 2548 ms |
| 1024 | 4680 ms | 4796 ms |

Our own verification times land at 6.0 / 7.7 / 10.4 ms here against 9 / 12 / 20 ms
in the table; the table's figure additionally includes the Groth16 and CP-link
verification measured by the Go driver (2.4 and 1.2 ms at `R = 256`).

## Caveats

* The host-side PRF is a width-2 Poseidon permutation with 8 full and 50 partial
  rounds and an `x^5` S-box, written out directly in `mask.rs` — the same width
  and round counts as the Poseidon2 in the gnark circuits, which differs only in
  its linear layer (a 2x2 matrix at this width either way).  Going through
  `PoseidonSponge` instead costs 3.2x more, and since masking is the *dominant*
  stage of our own scheme at large `ell`, that overhead would have landed
  straight in the headline number.
* For VECK\* and for us the subset polynomial is blinded with a degree-1 multiple
  of the vanishing polynomial, as in `PFDE-KZG`'s own benchmark, so the opened
  value differs from `sum_i L_i(alpha) x_i` by `t(alpha) Z_S(alpha)`.  The work is
  identical either way, but a deployment has to reconcile that term with the
  circuit's `U`.
* VECK+'s subset polynomial is deliberately *not* blinded: its DLEQ proof is only
  sound if the opened value equals `sum_i L_i(alpha) x_i` exactly.
* `LOW_DEGREE_DIVISOR_LIMIT` in `PFDE-KZG/*/src/divide.rs` decides which division
  strategy `(phi - f_S) / Z_S` uses.  It is a cache property, so re-measure it
  before quoting `kzg_proof_ms` on new hardware:
  `cargo test --release -- --ignored divide_threshold_probe --nocapture`.  It was
  650, which made `R = 1024` miss the faster path and cost it 14%; the measured
  crossover is between 1280 and 1536, so it is now 1280.
* VECK\*'s KZG group is instantiated as BW6-761 rather than its inner BLS12-377,
  matching the reference benchmark this comparison extends.
* `R + 2 <= ell` is required for the subset relation to be non-degenerate, so
  `(ell, R) = (2^10, 1024)` is skipped.
* The CP-link layer is the Kiltz–Wee QA-NIZK stand-in from the reference
  implementation, run on dummy commitments; see `PFDE-SNARK/*/main.go`.
