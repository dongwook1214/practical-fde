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
`extrapolated=true`, are drawn dashed in the figure, and skip verification (there
are no ciphertexts to check).  `--no-extrapolate` measures everything, at the cost
of a multi-day run.

Nothing else is extrapolated: encoding, commitment, the masking of the codeword,
sampling, the subset polynomial, the quotient and every opening are measured at
the full file size for every row.

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

## Caveats

* The host-side PRF is the arkworks Poseidon sponge (width 3, `x^5`), used as a
  stand-in for the Poseidon2 in the gnark circuits.  Poseidon2 has a cheaper
  linear layer, so this slightly overstates the masking cost — identically for
  VECK\* and for us.
* VECK\*'s KZG group is instantiated as BW6-761 rather than its inner BLS12-377,
  matching the reference benchmark this comparison extends.
* `R + 2 <= ell` is required for the subset relation to be non-degenerate, so
  `(ell, R) = (2^10, 1024)` is skipped.
* The CP-link layer is the Kiltz–Wee QA-NIZK stand-in from the reference
  implementation, run on dummy commitments; see `PFDE-SNARK/*/main.go`.
