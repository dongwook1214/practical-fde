#!/usr/bin/env python3
"""Join the Rust (KZG) and Go (SNARK) measurements into end-to-end numbers.

Inputs  (in --results):
    kzg_<scheme>_<curve>.csv   one row per (file size, R), written by `pfde-bench`
    snark.csv                  one row per (scheme, curve, R), written by the Go drivers

Outputs (in --results):
    end_to_end.csv             the joined table used by plot.py and the paper
    pgfplots/proving_time.tex  \\addplot coordinate blocks, ready to paste into main.tex
    pgfplots/snark_table.tex   the SNARK resource table rows

The SNARK cost depends only on R, never on the file size, so it is added as a
constant to every file size of the matching (scheme, curve, R).
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

SCHEME_LABEL = {
    "veck": r"VECK\(_{\mathrm{EL}}\)",
    "veck-plus": r"VECK\(^{+}_{\mathrm{EL}}\)",
    "veck-star": r"VECK\(^{\star}_{\mathrm{EL}}\)",
    "ours": "Ours",
}

# Stages that make up the online sender cost.
PROVE_STAGES = [
    "encode_ms",
    "commit_ms",
    "encrypt_ms",
    "sample_ms",
    "subset_ms",
    "sample_crypto_ms",
    "kzg_proof_ms",
]


def read_csv(path: Path) -> list[dict]:
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def as_float(row: dict, key: str) -> float:
    value = row.get(key, "")
    return float(value) if value not in (None, "") else 0.0


def load_snark(results: Path) -> dict[tuple[str, str, int], dict]:
    path = results / "snark.csv"
    if not path.exists():
        print(f"note: {path} not found; end-to-end totals will omit the SNARK")
        return {}
    table = {}
    for row in read_csv(path):
        key = (row["scheme"], row["curve"], int(row["R"]))
        table[key] = row
    return table


def build(results: Path) -> list[dict]:
    snark = load_snark(results)
    joined = []
    for path in sorted(results.glob("kzg_*.csv")):
        for row in read_csv(path):
            scheme, curve, r = row["scheme"], row["curve"], int(row["R"])
            kzg_prove = sum(as_float(row, stage) for stage in PROVE_STAGES)
            kzg_verify = as_float(row, "verify_ms") if row.get("verify_ms") else None

            snark_row = snark.get((scheme, curve, r))
            snark_prove = 0.0
            snark_verify = 0.0
            snark_setup = 0.0
            if snark_row is not None:
                snark_prove = as_float(snark_row, "prove_ms") + as_float(
                    snark_row, "cplink_prove_ms"
                )
                snark_verify = as_float(snark_row, "verify_ms") + as_float(
                    snark_row, "cplink_verify_ms"
                )
                snark_setup = as_float(snark_row, "setup_ms")

            joined.append(
                {
                    "scheme": scheme,
                    "curve": curve,
                    "log_ell": int(row["log_ell"]),
                    "ell": int(row["ell"]),
                    "R": r,
                    "beta": float(row["beta"]),
                    "m": int(row["m"]),
                    "encode_ms": as_float(row, "encode_ms"),
                    "commit_ms": as_float(row, "commit_ms"),
                    "encrypt_ms": as_float(row, "encrypt_ms"),
                    "sample_ms": as_float(row, "sample_ms"),
                    "subset_ms": as_float(row, "subset_ms"),
                    "sample_crypto_ms": as_float(row, "sample_crypto_ms"),
                    "kzg_proof_ms": as_float(row, "kzg_proof_ms"),
                    "kzg_prove_ms": kzg_prove,
                    "snark_prove_ms": snark_prove,
                    "snark_setup_ms": snark_setup,
                    "prove_total_ms": kzg_prove + snark_prove,
                    "kzg_verify_ms": kzg_verify if kzg_verify is not None else "",
                    "snark_verify_ms": snark_verify,
                    "verify_total_ms": (kzg_verify + snark_verify)
                    if kzg_verify is not None
                    else "",
                    "extrapolated": row.get("extrapolated", "false"),
                    "verified": row.get("verified", "false"),
                    "has_snark": snark_row is not None,
                }
            )
    joined.sort(key=lambda row: (row["scheme"], row["curve"], row["R"], row["log_ell"]))
    return joined


def write_end_to_end(results: Path, rows: list[dict]) -> Path:
    path = results / "end_to_end.csv"
    if not rows:
        raise SystemExit("no kzg_*.csv files found; run the benchmark first")
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return path


def write_pgfplots(results: Path, rows: list[dict]) -> Path:
    out_dir = results / "pgfplots"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "proving_time.tex"

    series: dict[tuple[str, str, int], list[tuple[int, float]]] = {}
    for row in rows:
        key = (row["scheme"], row["curve"], row["R"])
        series.setdefault(key, []).append((row["ell"], row["prove_total_ms"] / 1000.0))

    lines = [
        "% Generated by benchmarks/scripts/aggregate.py -- do not edit by hand.",
        "% End-to-end sender time in seconds against the original file size in field elements.",
        "",
    ]
    for (scheme, curve, r), points in sorted(series.items()):
        lines.append(f"% {SCHEME_LABEL.get(scheme, scheme)} ({curve}), R = {r}")
        lines.append("\\addplot coordinates {")
        for ell, seconds in sorted(points):
            lines.append(f"    ({ell},{seconds:.4f})")
        lines.append("};")
        lines.append("")
    path.write_text("\n".join(lines))
    return path


def write_snark_table(results: Path) -> Path | None:
    source = results / "snark.csv"
    if not source.exists():
        return None
    out_dir = results / "pgfplots"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "snark_table.tex"

    rows = read_csv(source)
    grouped: dict[tuple[str, str], dict[int, dict]] = {}
    for row in rows:
        grouped.setdefault((row["scheme"], row["curve"]), {})[int(row["R"])] = row

    def mib(value: str) -> str:
        size = float(value)
        return "--" if size < 0 else f"${size / (1024 * 1024):.2f}$\\,MiB"

    def seconds(value: str) -> str:
        return f"${float(value) / 1000:.3f}$\\,s"

    lines = ["% Generated by benchmarks/scripts/aggregate.py -- do not edit by hand.", ""]
    for (scheme, curve), by_r in sorted(grouped.items()):
        label = SCHEME_LABEL.get(scheme, scheme)
        ordered = [by_r[r] for r in sorted(by_r)]
        lines.append(f"\\multirow{{5}}{{*}}{{{label} ({curve})}}")
        lines.append(
            "  & constraints       & "
            + " & ".join(f"${int(row['constraints']):,}$".replace(",", "{,}") for row in ordered)
            + " \\\\"
        )
        for metric, key in (("setup time", "setup_ms"), ("proving time", "prove_ms")):
            lines.append(
                f"  & {metric:<17} & "
                + " & ".join(seconds(row[key]) for row in ordered)
                + " \\\\"
            )
        lines.append(
            "  & verification time & "
            + " & ".join(f"${float(row['verify_ms']):.2f}$\\,ms" for row in ordered)
            + " \\\\"
        )
        lines.append(
            "  & CRS size          & "
            + " & ".join(mib(row["crs_bytes"]) for row in ordered)
            + " \\\\"
        )
        lines.append("\\midrule")
        lines.append("")
    path.write_text("\n".join(lines))
    return path


def summarise(rows: list[dict]) -> None:
    print()
    print(f"{'scheme':<10} {'curve':<10} {'R':>5} {'ell':>9} {'prove (s)':>11} {'verify (ms)':>12}  flags")
    print("-" * 68)
    for row in rows:
        verify = row["verify_total_ms"]
        flags = []
        if row["extrapolated"] == "true":
            flags.append("extrapolated")
        if not row["has_snark"]:
            flags.append("no-snark")
        print(
            f"{row['scheme']:<10} {row['curve']:<10} {row['R']:>5} {row['ell']:>9} "
            f"{row['prove_total_ms'] / 1000:>11.3f} "
            f"{(f'{verify:.1f}' if verify != '' else '-'):>12}  {','.join(flags)}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--results",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "results",
        help="directory holding kzg_*.csv and snark.csv",
    )
    parser.add_argument("--quiet", action="store_true", help="do not print the summary table")
    args = parser.parse_args()

    rows = build(args.results)
    print(f"wrote {write_end_to_end(args.results, rows)}")
    print(f"wrote {write_pgfplots(args.results, rows)}")
    table = write_snark_table(args.results)
    if table is not None:
        print(f"wrote {table}")
    if not args.quiet:
        summarise(rows)


if __name__ == "__main__":
    main()
