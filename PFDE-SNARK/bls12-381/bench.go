package main

// Benchmark harness shared by the SNARK drivers: it records the stage timings
// that `main.go` already prints and, with `-csv`, appends them as one row so the
// aggregation script can join them with the Rust (KZG) measurements.
//
// The number of sampled positions R is the compile-time constant `N`, selected
// with a build tag:
//
//	go run -tags r256  .   # R = 256
//	go run -tags r512  .   # R = 512
//	go run -tags r1024 .   # R = 1024

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/consensys/gnark/backend/groth16"
)

const (
	defaultSchemeTag = "ours"
	defaultCurveTag  = "bls12-381"
)

// benchMetrics holds the durations measured inside setup/prove/verify.
type benchMetrics struct {
	compile      time.Duration
	setup        time.Duration
	prove        time.Duration
	verify       time.Duration
	cpLinkSetup  time.Duration
	cpLinkProve  time.Duration
	cpLinkVerify time.Duration
}

var metrics benchMetrics

var (
	csvPath    = flag.String("csv", "", "append one CSV row to this file")
	schemeTag  = flag.String("scheme", defaultSchemeTag, "scheme label written to the CSV")
	curveTag   = flag.String("curve", defaultCurveTag, "curve label written to the CSV")
	measureCRS = flag.Bool("crs-size", true, "serialise the proving key to measure the CRS size")
	// The reference VECK* driver hard-coded GOMAXPROCS(32) while ours used
	// runtime.NumCPU(); a comparison needs both on the same budget, so it is a
	// flag and it is recorded in the CSV rather than being implied.
	benchCores = flag.Int("cores", runtime.NumCPU(), "GOMAXPROCS for this run")
)

const benchHeader = "scheme,curve,R,cores,constraints,compile_ms,setup_ms,prove_ms,verify_ms," +
	"cplink_setup_ms,cplink_prove_ms,cplink_verify_ms,crs_bytes"

// parseBenchFlags must be called first thing in main().
func parseBenchFlags() {
	flag.Parse()
}

type countingWriter struct{ n int64 }

func (w *countingWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	return len(p), nil
}

func milliseconds(d time.Duration) float64 {
	return float64(d.Nanoseconds()) / 1e6
}

// crsBytes reports the compressed size of the circuit-specific proving key.
func crsBytes(pk groth16.ProvingKey) int64 {
	if !*measureCRS || pk == nil {
		return -1
	}
	writer, ok := interface{}(pk).(io.WriterTo)
	if !ok {
		return -1
	}
	var counter countingWriter
	if _, err := writer.WriteTo(&counter); err != nil {
		return -1
	}
	return counter.n
}

func writeBenchRow(constraints int, pk groth16.ProvingKey) {
	row := fmt.Sprintf("%s,%s,%d,%d,%d,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%d",
		*schemeTag, *curveTag, N, *benchCores, constraints,
		milliseconds(metrics.compile),
		milliseconds(metrics.setup),
		milliseconds(metrics.prove),
		milliseconds(metrics.verify),
		milliseconds(metrics.cpLinkSetup),
		milliseconds(metrics.cpLinkProve),
		milliseconds(metrics.cpLinkVerify),
		crsBytes(pk),
	)
	fmt.Println(benchHeader)
	fmt.Println(row)

	if *csvPath == "" {
		return
	}
	if dir := filepath.Dir(*csvPath); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "cannot create %s: %v\n", dir, err)
			return
		}
	}
	needsHeader := true
	if info, err := os.Stat(*csvPath); err == nil && info.Size() > 0 {
		needsHeader = false
	}
	file, err := os.OpenFile(*csvPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot open %s: %v\n", *csvPath, err)
		return
	}
	defer file.Close()
	if needsHeader {
		fmt.Fprintln(file, benchHeader)
	}
	fmt.Fprintln(file, row)
}
