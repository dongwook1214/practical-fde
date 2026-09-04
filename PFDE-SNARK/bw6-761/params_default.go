//go:build !r2384 && !r1053 && !r609 && !r386

package main

// Default when no r<N> build tag is given: beta = 1.5.
const N = 609
