#!/usr/bin/env bash
#
# Full benchmark sweep used in the paper.
#
#   ./benchmarks/scripts/run_all.sh
#
# Environment overrides:
#   MIN_LOG / MAX_LOG        file-size exponents             (default 10 / 20)
#   SUBSETS                  sample counts R                 (default 256,512,1024)
#   RESULTS                  output directory                (default benchmarks/results)
#   VECK_CAP                 measured prefix for base VECK   (default 14)
#   VECK_PLUS_CAP            measured prefix for VECK+       (default 16)
#   REPEAT                   samples per stage               (default 5)
#   REPEAT_BUDGET_MS         a stage over this is not repeated (default 2000)
#   ARCHIVE=0                do not archive previous results
#   SKIP_SNARK=1             skip the Go drivers
#   SKIP_KZG=1               skip the Rust driver
#
# The `*_CAP` values bound how much of the payload the *linear* public-key stages
# are actually run on; larger files reuse the measured per-symbol cost.  Set both
# to a value >= MAX_LOG (or pass --no-extrapolate) for a fully measured, multi-day
# run.
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
RESULTS=${RESULTS:-$ROOT/benchmarks/results}
MIN_LOG=${MIN_LOG:-10}
MAX_LOG=${MAX_LOG:-20}
SUBSETS=${SUBSETS:-256,512,1024}
VECK_CAP=${VECK_CAP:-14}
VECK_PLUS_CAP=${VECK_PLUS_CAP:-16}
REPEAT=${REPEAT:-5}
REPEAT_BUDGET_MS=${REPEAT_BUDGET_MS:-2000}

mkdir -p "$RESULTS"
failures=0

# A full sweep costs hours, so never overwrite a previous one silently.
if [ "${ARCHIVE:-1}" = "1" ]; then
  shopt -s nullglob
  previous=("$RESULTS"/*.csv)
  shopt -u nullglob
  [ -f "$RESULTS/run_info.txt" ] && previous+=("$RESULTS/run_info.txt")
  if [ ${#previous[@]} -gt 0 ]; then
    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    mkdir -p "$RESULTS/archive/$stamp"
    cp -p "${previous[@]}" "$RESULTS/archive/$stamp/"
    echo "archived ${#previous[@]} file(s) from a previous run to results/archive/$stamp"
  fi
fi

# Provenance, so a CSV is never orphaned from the machine and parameters that
# produced it -- this is what the paper's experimental-setup paragraph needs.
{
  echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host=$(hostname)"
  echo "uname=$(uname -smr)"
  echo "cpu=$(sysctl -n machdep.cpu.brand_string 2>/dev/null \
      || (grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//') \
      || echo unknown)"
  echo "cores=$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo unknown)"
  echo "memory_bytes=$(sysctl -n hw.memsize 2>/dev/null || echo unknown)"
  echo "git_commit=$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  echo "git_dirty=$([ -n "$(git -C "$ROOT" status --porcelain 2>/dev/null)" ] && echo yes || echo no)"
  echo "rustc=$(rustc --version 2>/dev/null || echo absent)"
  echo "go=$(go version 2>/dev/null || echo absent)"
  echo "min_log=$MIN_LOG"
  echo "max_log=$MAX_LOG"
  echo "subsets=$SUBSETS"
  echo "veck_cap=$VECK_CAP"
  echo "veck_plus_cap=$VECK_PLUS_CAP"
  echo "repeat=$REPEAT"
  echo "repeat_budget_ms=$REPEAT_BUDGET_MS"
  echo "skip_kzg=${SKIP_KZG:-0}"
  echo "skip_snark=${SKIP_SNARK:-0}"
} > "$RESULTS/run_info.txt"
echo "=== run_info.txt ================================================="
cat "$RESULTS/run_info.txt"

if [ "${SKIP_KZG:-0}" != "1" ]; then
  echo "=== encoding / encryption / KZG (Rust) ==========================="
  ( cd "$ROOT/benchmarks/kzg" && cargo build --release ) || { echo "cargo build failed"; exit 1; }

  run_kzg() {
    local scheme=$1 curve=$2
    shift 2
    echo "--- $scheme on $curve"
    ( cd "$ROOT/benchmarks/kzg" && ./target/release/pfde-bench \
        --scheme "$scheme" --curve "$curve" \
        --min-log "$MIN_LOG" --max-log "$MAX_LOG" --subsets "$SUBSETS" \
        --repeat "$REPEAT" --repeat-budget-ms "$REPEAT_BUDGET_MS" \
        --out "$RESULTS/kzg_${scheme}_${curve}.csv" "$@" ) \
      || { echo "!!! $scheme/$curve failed"; failures=$((failures + 1)); }
  }

  # BLS12-381: every scheme that can live on a plain pairing-friendly curve.
  run_kzg ours       bls12-381
  run_kzg veck-plus  bls12-381 --max-measured-log "$VECK_PLUS_CAP"
  run_kzg veck       bls12-381 --max-measured-log "$VECK_CAP"
  # BW6-761: ours and VECK*, whose in-circuit ElGamal forces the 2-chain.
  run_kzg ours       bw6-761
  run_kzg veck-star  bw6-761
fi

if [ "${SKIP_SNARK:-0}" != "1" ]; then
  echo "=== Groth16 + CP-link (Go) ======================================="
  SNARK_CSV="$RESULTS/snark.csv"
  rm -f "$SNARK_CSV"
  if ! command -v go >/dev/null 2>&1; then
    echo "!!! go is not on PATH; skipping the SNARK drivers"
    failures=$((failures + 1))
  else
    for tag in ${SUBSETS//,/ }; do
      for dir in "$ROOT/PFDE-SNARK/bls12-381" "$ROOT/PFDE-SNARK/bw6-761" \
                 "$ROOT/baselines/veck-star-snark"; do
        label="$(basename "$(dirname "$dir")")/$(basename "$dir")"
        echo "--- $label at R=$tag"
        ( cd "$dir" && go run -tags "r$tag" . -csv "$SNARK_CSV" ) \
          || { echo "!!! $label at R=$tag failed"; failures=$((failures + 1)); }
      done
    done
  fi
fi

# Aggregate whatever succeeded: a failure in the Go phase must not throw away
# hours of Rust measurements.
echo "=== aggregate ===================================================="
python3 "$ROOT/benchmarks/scripts/aggregate.py" --results "$RESULTS" \
  || failures=$((failures + 1))
python3 "$ROOT/benchmarks/scripts/plot.py" \
  || echo "(no preview figure; matplotlib missing or the data is incomplete)"

if [ "$failures" -gt 0 ]; then
  echo
  echo "!!! $failures step(s) failed; the CSVs above cover only what succeeded"
  exit 1
fi
echo "done"
