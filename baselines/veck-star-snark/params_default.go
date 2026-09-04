//go:build !r2384 && !r1053 && !r609 && !r386

package main

// Default when no r<N> build tag is given: beta = 1.5.
const N = 609

// There is deliberately no r2384 variant here: beta = 1.1 needs 2384
// samples, and only our scheme is measured in that regime.
