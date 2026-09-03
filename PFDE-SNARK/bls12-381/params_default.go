//go:build !r256 && !r512 && !r1024

package main

// Default sample count when no r<N> build tag is given.
const N = 512
