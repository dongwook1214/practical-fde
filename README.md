# Practical-FDE

Reference implementations accompanying our paper on **Practical Fair Data Exchange**.

The repository collects two complementary prototypes, each provided over two
pairing-friendly curves so that the benchmark numbers reported in the paper can
be reproduced on both a standard and a large-scalar-field setting.

```
Practical-fde/
├── PFDE-KZG/          # KZG-based verifiable encryption / commitment prototype (Rust, arkworks)
│   ├── bls12-381/     #   BLS12-381 instantiation
│   └── bw6-761/       #   BW6-761  instantiation
└── PFDE-SNARK/        # Groth16 SNARK prototype with CP-Link (Go, gnark)
    ├── bls12-381/     #   BLS12-381 instantiation
    └── bw6-761/       #   BW6-761  instantiation
```

## PFDE-KZG (Rust)

A KZG-commitment–based prototype built on the [arkworks](https://arkworks.rs/)
ecosystem (`ark-poly-commit`, `ark-ec`, `ark-poly`). It implements the
polynomial commitment, subset division, and verifiable-encryption checks used
by the PFDE protocol.

| Variant     | Curve     | Dependency      |
| ----------- | --------- | --------------- |
| `bls12-381` | BLS12-381 | `ark-bls12-381` |
| `bw6-761`   | BW6-761   | `ark-bw6-761`   |

Build / test:

```bash
cd PFDE-KZG/bls12-381   # or bw6-761
cargo build --release
cargo test --release -- --nocapture
```

## PFDE-SNARK (Go)

A Groth16 circuit implemented with [gnark](https://github.com/consensys/gnark).
The circuit proves the encryption relation `CT[i] == X[i] + Poseidon2(SK, SRPrime[i])`
together with the linear combination `∑ X[i]·L[i] == U`. The `SK` and `U` values
are committed witnesses linked via **CP-Link** rather than being proven
in-circuit (a dummy CP-Link is used for benchmarking, as noted in the source).

| Variant     | Curve     | Package                      |
| ----------- | --------- | ---------------------------- |
| `bls12-381` | BLS12-381 | `gnark-crypto/ecc/bls12-381` |
| `bw6-761`   | BW6-761   | `gnark-crypto/ecc/bw6-761`   |

Build / run:

```bash
cd PFDE-SNARK/bls12-381   # or bw6-761
go run .
```

## Provenance

Each directory is a clean export (tracked files only, build artifacts excluded)
of the corresponding branch in the original development repositories:

| Directory              | Source repo | Branch             |
| ---------------------- | ----------- | ------------------ |
| `PFDE-KZG/bls12-381`   | PFDE-KZG    | `for-benchmark`    |
| `PFDE-KZG/bw6-761`     | PFDE-KZG    | `for-benchmark-bw` |
| `PFDE-SNARK/bls12-381` | PFDE-SNARK  | `main`             |
| `PFDE-SNARK/bw6-761`   | PFDE-SNARK  | `bw`               |
