#!/usr/bin/env python3
"""Preview figure for the end-to-end benchmark.

The paper itself uses the pgfplots blocks emitted by `aggregate.py`; this script
renders the same data with matplotlib so the numbers can be eyeballed without a
LaTeX round trip.

One panel per sample count R (small multiples), because 5 schemes x 3 values of R
in a single axes would need cycled colours.  Dashed segments mark file sizes whose
linear public-key stages were extrapolated rather than measured.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402

# Same hues as the paper's \definecolor declarations, plus one for base VECK.
# Checked for CVD separation and chroma; the green is the paper's own and sits
# just under 3:1 against white, so every series also carries a distinct marker.
SERIES = [
    ("veck", "bls12-381", "VECK (BLS12-381)", "#8A6D00", "v"),
    ("veck-plus", "bls12-381", "VECK+ (BLS12-381)", "#00B180", "s"),
    ("veck-star", "bw6-761", "VECK* (BW6-761)", "#0077B1", "^"),
    ("ours", "bw6-761", "Ours (BW6-761)", "#7E2F8E", "D"),
    ("ours", "bls12-381", "Ours (BLS12-381)", "#B13A00", "o"),
]

INK = "#1c1c1c"
MUTED = "#6b6b6b"
GRID = "#d8d8d8"
SURFACE = "#fcfcfb"


def load(path: Path) -> list[dict]:
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    results = Path(__file__).resolve().parents[1] / "results"
    parser.add_argument("--input", type=Path, default=results / "end_to_end.csv")
    parser.add_argument("--out", type=Path, default=results / "figures" / "end_to_end")
    args = parser.parse_args()

    rows = load(args.input)
    # R = 0 marks base VECK, which neither codes nor samples; it is drawn in
    # every panel as the uncoded reference.
    sample_counts = sorted({int(row["R"]) for row in rows if int(row["R"]) > 0})

    fig, axes = plt.subplots(
        1,
        len(sample_counts),
        figsize=(4.1 * len(sample_counts), 3.6),
        sharey=True,
        facecolor=SURFACE,
    )
    if len(sample_counts) == 1:
        axes = [axes]

    for axis, r in zip(axes, sample_counts):
        axis.set_facecolor(SURFACE)
        for scheme, curve, _label, color, marker in SERIES:
            points = [
                row
                for row in rows
                if row["scheme"] == scheme
                and row["curve"] == curve
                and int(row["R"]) in (r, 0)
            ]
            points.sort(key=lambda row: int(row["ell"]))
            if not points:
                continue
            x = [int(row["ell"]) for row in points]
            y = [float(row["prove_total_ms"]) / 1000.0 for row in points]

            # Solid where the linear stages were measured, dashed where the
            # per-symbol cost was extrapolated.
            for index in range(len(x) - 1):
                dashed = points[index + 1]["extrapolated"] == "true"
                axis.plot(
                    x[index : index + 2],
                    y[index : index + 2],
                    color=color,
                    linewidth=1.8,
                    linestyle=(0, (4, 2)) if dashed else "-",
                    zorder=3,
                )
            axis.plot(
                x,
                y,
                color=color,
                linewidth=0,
                marker=marker,
                markersize=5,
                markeredgecolor=SURFACE,
                markeredgewidth=0.7,
                zorder=4,
            )

        axis.set_xscale("log", base=2)
        axis.set_yscale("log")
        axis.grid(True, which="major", color=GRID, linewidth=0.6, linestyle="-", zorder=0)
        axis.grid(True, which="minor", color=GRID, linewidth=0.4, linestyle=":", zorder=0)
        axis.set_axisbelow(True)
        for side in ("top", "right"):
            axis.spines[side].set_visible(False)
        for side in ("left", "bottom"):
            axis.spines[side].set_color(GRID)
        axis.tick_params(colors=MUTED, labelsize=9)
        axis.set_xlabel("file size $\\ell$ (field elements)", color=MUTED, fontsize=9)
        axis.set_title(f"$R = {r}$", color=INK, fontsize=10, pad=8)

    axes[0].set_ylabel("end-to-end sender time (s)", color=MUTED, fontsize=9)

    handles = [
        Line2D([], [], color=color, marker=marker, markersize=5, linewidth=1.8, label=label)
        for _scheme, _curve, label, color, marker in SERIES
    ]
    handles.append(
        Line2D([], [], color=MUTED, linewidth=1.8, linestyle=(0, (4, 2)), label="extrapolated")
    )
    fig.legend(
        handles=handles,
        loc="lower center",
        ncol=3,
        frameon=False,
        fontsize=9,
        labelcolor=INK,
        bbox_to_anchor=(0.5, -0.02),
    )
    fig.suptitle(
        "End-to-end sender cost: encoding, encryption, KZG proof and SNARK",
        color=INK,
        fontsize=11,
    )
    fig.tight_layout(rect=(0, 0.1, 1, 0.94))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    for suffix in (".pdf", ".png"):
        fig.savefig(args.out.with_suffix(suffix), dpi=200, facecolor=SURFACE)
        print(f"wrote {args.out.with_suffix(suffix)}")


if __name__ == "__main__":
    main()
