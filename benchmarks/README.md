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

`--help` lists every option.  The powers of tau are generated once into
`benchmarks/kzg/.cache/srs/<curve>/` and reused; at `ell = 2^20` that is roughly
300 MiB for BLS12-381 and 800 MiB for BW6-761.

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

The Go drivers are covered by `go vet` rather than tests; run it after any edit.

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
* VECK\*'s KZG group is instantiated as BW6-761 rather than its inner BLS12-377,
  matching the reference benchmark this comparison extends.
* `R + 2 <= ell` is required for the subset relation to be non-degenerate, so
  `(ell, R) = (2^10, 1024)` is skipped.
* The CP-link layer is the Kiltz–Wee QA-NIZK stand-in from the reference
  implementation, run on dummy commitments; see `PFDE-SNARK/*/main.go`.
