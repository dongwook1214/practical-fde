# Practical-FDE

Reference implementation and benchmark suite accompanying our paper on
**Practical Fair Data Exchange**.

```
Practical-fde/
├── PFDE-KZG/            # our KZG layer (Rust, arkworks)
│   ├── bls12-381/       #   BLS12-381 instantiation
│   └── bw6-761/         #   BW6-761  instantiation
├── PFDE-SNARK/          # our Groth16 circuit + CP-link (Go, gnark)
│   ├── bls12-381/
│   └── bw6-761/
├── baselines/           # vendored reference implementations we compare against
│   ├── fde/             #   VECK_EL / VECK+_EL primitives (Rust)
│   └── veck-star-snark/ #   VECK*_EL circuit (Go)
└── benchmarks/          # the end-to-end evaluation
    ├── kzg/             #   encoding + encryption + KZG, all schemes, both curves
    ├── scripts/         #   run_all.sh, aggregate.py, plot.py
    └── results/         #   CSVs, pgfplots blocks, figures
```

## Quickstart

```bash
./benchmarks/scripts/run_all.sh          # full sweep: 2^10 .. 2^20, R in {256,512,1024}
MAX_LOG=14 ./benchmarks/scripts/run_all.sh   # a few minutes instead of a few hours
```

Results land in `benchmarks/results/`, including `pgfplots/` blocks that paste
straight into the paper.  See [`benchmarks/README.md`](benchmarks/README.md) for
what each stage measures, which scheme runs on which curve, and where the numbers
are extrapolated rather than measured.

## PFDE-KZG (Rust)

A KZG-commitment prototype built on [arkworks](https://arkworks.rs/)
(`ark-poly-commit`, `ark-ec`, `ark-poly`): the polynomial commitment, the subset
division, and the verifiable-encryption checks used by PFDE.

| Variant     | Curve     | Dependency      |
| ----------- | --------- | --------------- |
| `bls12-381` | BLS12-381 | `ark-bls12-381` |
| `bw6-761`   | BW6-761   | `ark-bw6-761`   |

The two directories contain the *same* library: `commit`, `divide` and `veck` are
generic over `ark_ec::pairing::Pairing`, and only the crates' own tests and
`main.rs` pin a curve.  The benchmark links one of them and instantiates both
curves from it.

```bash
cd PFDE-KZG/bls12-381   # or bw6-761
cargo test --release -- --nocapture
cargo run --release -- setup-cache --range 1048576   # pre-generate powers of tau
```

## PFDE-SNARK (Go)

A Groth16 circuit in [gnark](https://github.com/consensys/gnark).  It proves the
encryption relation `CT[i] == X[i] + Poseidon2(SK, SRPrime[i])` together with the
linear combination `sum_i X[i]*L[i] == U`.  `SK` and `U` are committed witnesses
linked outside the circuit via **CP-Link** (a Kiltz–Wee QA-NIZK; a dummy instance
is used for benchmarking, as noted in the source), so the circuit contains no
elliptic-curve gadget — which is what lets it run on BLS12-381 rather than being
forced onto a 2-chain.

| Variant     | Curve     | Package                      |
| ----------- | --------- | ---------------------------- |
| `bls12-381` | BLS12-381 | `gnark-crypto/ecc/bls12-381` |
| `bw6-761`   | BW6-761   | `gnark-crypto/ecc/bw6-761`   |

The number of sampled positions `R` is a compile-time constant chosen by build
tag:

```bash
cd PFDE-SNARK/bls12-381
go run -tags r256  .
go run -tags r512  . -csv ../../benchmarks/results/snark.csv
go run -tags r1024 .
```

## Baselines

`baselines/` holds vendored copies of the implementations we compare against, so
the whole evaluation reproduces from one clone.  See
[`baselines/README.md`](baselines/README.md) for provenance and for the list of
changes — in particular the replacement of upstream's FFT-subdomain "random"
subset with genuine random sampling and a general polynomial division, without
which the baselines would enjoy a division speed-up the protocol does not admit.
