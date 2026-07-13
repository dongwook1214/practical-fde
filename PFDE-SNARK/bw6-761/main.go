package main

import (
	"fmt"
	"log"
	"math/big"
	"runtime"
	"sync"
	"time"

	stdHash "github.com/consensys/gnark/std/hash"
	stdPermutation "github.com/consensys/gnark/std/permutation/poseidon2"

	"github.com/consensys/gnark-crypto/ecc"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	bw6761fr "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr/poseidon2"
	embeddedTed "github.com/consensys/gnark-crypto/ecc/bw6-761/twistededwards"
	gcTed "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	ted "github.com/consensys/gnark/std/algebra/native/twistededwards"
)

const N = 512

// Circuit encodes:
//
//	tempO = 0
//	For i in [0..N+1]:
//		CT[i] == X[i] + Poseidon2(SK, SRPrime[i])
//		tempO += X[i] * L[i]
//	tempO == U
//
// VK == H^SK is no longer proven in-circuit: SK is a committed witness and the
// relation is proven outside the SNARK via CP-Link (just like U).
type Circuit struct {
	// Public inputs
	SRPrime [N + 2]frontend.Variable `gnark:",public"`
	CT      [N + 2]frontend.Variable `gnark:",public"`
	L       [N + 2]frontend.Variable `gnark:",public"`

	// committed witnesses
	// We did not implement the actual LegoGro16.
	// Instead, for benchmarking purposes, we ran CP-Link with dummy data.
	//
	// SK is committed and linked via CP-Link instead of proving VK == H^SK
	// inside the circuit, just like U.
	U  frontend.Variable
	SK frontend.Variable

	// free Witnesses
	X [N + 2]frontend.Variable
}

// rangeCheckEmbeddedFr enforces 0 <= v <= r-1 where r is the embedded twisted Edwards scalar modulus.
// It (1) constrains v to n bits (nbits = bitlen(r-1)) and (2) proves v <= r-1
// using an MSB-first lexicographic compare against the constant (r-1).
func rangeCheckEmbeddedFr(api frontend.API, v frontend.Variable) error {
	curve, err := ted.NewEdCurve(api, gcTed.BW6_761)
	if err != nil {
		return err
	}
	q := curve.Params().Order
	var bound big.Int
	bound.Sub(q, big.NewInt(1)) // r - 1
	nbits := bound.BitLen()

	// Decompose v into nbits bits (LSB-first). This already enforces v < 2^nbits.
	bits := api.ToBinary(v, nbits)

	// Lexicographic check: ensure v <= bound.
	// We maintain two boolean flags while scanning MSB->LSB:
	//  equal = 1 iff all higher bits matched so far
	//  less  = 1 iff v is already proven strictly less at a higher bit
	// At the end, we assert equal + less == 1  (i.e., v == bound OR v < bound).
	var equal frontend.Variable = 1
	var less frontend.Variable = 0

	for i := nbits - 1; i >= 0; i-- {
		vi := bits[i]      // bit i of v (0 or 1)
		bi := bound.Bit(i) // bit i of bound (constant 0 or 1)

		// vi < bi  <=>  (1 - vi) && bi
		viLtBi := api.Mul(api.Sub(1, vi), int(bi))

		// If we were equal so far and now vi < bi, then v < bound forever after.
		less = api.Add(less, api.Mul(equal, viLtBi))

		// Update "equal": stays 1 only if current bits are equal.
		// If bi == 0: equal <- equal && (vi == 0)  -> equal * (1 - vi)
		// If bi == 1: equal <- equal && (vi == 1)  -> equal * vi
		if bi == 0 {
			equal = api.Mul(equal, api.Sub(1, vi))
		} else {
			equal = api.Mul(equal, vi)
		}
	}

	// Both flags are boolean by construction; enforce the final condition.
	api.AssertIsBoolean(equal)
	api.AssertIsBoolean(less)
	api.AssertIsEqual(api.Add(equal, less), 1) // v == bound OR v < bound

	return nil
}

func (c *Circuit) Define(api frontend.API) error {
	// Range check for SK: SK < q (embedded twisted Edwards curve order)
	if err := rangeCheckEmbeddedFr(api, c.SK); err != nil {
		return err
	}

	var tempO frontend.Variable = 0

	// Poseidon2 permutation for BW6-761
	f, err := stdPermutation.NewPoseidon2FromParameters(api, 2, 8, 50)
	if err != nil {
		return err
	}
	hasher := stdHash.NewMerkleDamgardHasher(api, f, c.SK)

	for i := 0; i < N+2; i++ {
		// CT[i] == X[i] + Poseidon2(SK, SRPrime[i])
		hasher.Write(c.SRPrime[i])
		hi := hasher.Sum()
		api.AssertIsEqual(c.CT[i], api.Add(c.X[i], hi))

		// tempO += X[i] * L[i]
		tempO = api.Add(tempO, api.Mul(c.X[i], c.L[i]))
	}
	api.AssertIsEqual(tempO, c.U)
	return nil
}

func mustBig(a interface{}) *big.Int {
	res := new(big.Int)
	if b, ok := a.(*big.Int); ok {
		return b
	}
	if b, ok := a.(interface{ BigInt(*big.Int) *big.Int }); ok {
		b.BigInt(res)
		return res
	}
	if b, ok := a.(interface{ ToBigInt() *big.Int }); ok {
		return b.ToBigInt()
	}
	panic("not a BigInt-able type")
}

// CP-Link is the Kiltz-Wee QA-NIZK for linear subspaces (k = 1, SXDH):
// "Quasi-Adaptive NIZK for Linear Subspaces Revisited".
//
// For language L_{[M]_1} = { [y]_1 : exists x, y = M x } with M in G1^{n x t}:
//
//	pk: [P]_1 = [M^T k]_1            (t elements)
//	vk: [C]_2 = [a*k]_2 (n elements), [A]_2 = [a]_2
//	proof: [pi]_1 = [y^T k]_1        (single G1 element)
//	verify: prod_i e(y_i, C_i) = e(pi, A)
type cpLinkProvingKey struct {
	// [P]_1 = [M^T k]_1, one G1 element per witness column (length t).
	P []bw6761.G1Affine
}

type cpLinkVerifyingKey struct {
	// [C]_2 = [a*k]_2, one per equation row (length n), and [A]_2 = [a]_2.
	C []bw6761.G2Affine
	A bw6761.G2Affine
}

type cpLinkStatement struct {
	// The word [y]_1 = [M]_1 x, one G1 element per equation row (length n).
	// For our language: Y[0] = C (SNARK commitment), Y[1] = g^U, Y[2] = g^SK (= VK).
	Y []bw6761.G1Affine
}

type cpLinkProof struct {
	// Single G1 element, per Kiltz-Wee (k = 1).
	Pi bw6761.G1Affine
}

type cpLinkBenchmark struct {
	VK        cpLinkVerifyingKey
	Statement cpLinkStatement
	Proof     cpLinkProof
}

func randomFrElement() (bw6761fr.Element, error) {
	var e bw6761fr.Element
	_, err := e.SetRandom()
	return e, err
}

func samplePedersenLikeBases(size int) ([]bw6761.G1Affine, error) {
	bases := make([]bw6761.G1Affine, size)
	for i := range bases {
		s, err := randomFrElement()
		if err != nil {
			return nil, err
		}
		bases[i].ScalarMultiplicationBase(mustBig(&s))
	}
	return bases, nil
}

// setupDummyCPLink runs the Kiltz-Wee QA-NIZK "Gen" for the linear-subspace
// language L_{[M]_1} = { [y]_1 : exists x, y = M x }, instantiated at k = 1 (SXDH):
//
//	[P]_1 = [M^T k]_1   (proving key, t elements)
//	[C]_2 = [a*k]_2     (verifying key, n elements)
//	[A]_2 = [a]_2
//
// M is given row-major as M[i][j] in G1 (n equation rows, t witness columns).
// Benchmark stand-in: M uses freshly sampled bases instead of the real
// LegoGroth16 commitment key, so it measures cost without binding to a real proof.
func setupDummyCPLink(M [][]bw6761.G1Affine) (cpLinkProvingKey, cpLinkVerifyingKey, error) {
	n := len(M)
	if n == 0 {
		return cpLinkProvingKey{}, cpLinkVerifyingKey{}, fmt.Errorf("cp-link: empty language matrix")
	}
	t := len(M[0])

	// Trapdoor: k in Z_p^n, a in Z_p.
	k := make([]bw6761fr.Element, n)
	for i := range k {
		ki, err := randomFrElement()
		if err != nil {
			return cpLinkProvingKey{}, cpLinkVerifyingKey{}, err
		}
		k[i] = ki
	}
	a, err := randomFrElement()
	if err != nil {
		return cpLinkProvingKey{}, cpLinkVerifyingKey{}, err
	}

	// [P]_1: P_j = sum_i k_i * M[i][j].
	pk := cpLinkProvingKey{P: make([]bw6761.G1Affine, t)}
	for j := 0; j < t; j++ {
		var acc bw6761.G1Affine
		acc.SetInfinity()
		for i := 0; i < n; i++ {
			var term bw6761.G1Affine
			term.ScalarMultiplication(&M[i][j], mustBig(&k[i]))
			acc.Add(&acc, &term)
		}
		pk.P[j] = acc
	}

	// [C]_2: C_i = (a*k_i) * G2 ; [A]_2 = a * G2.
	vk := cpLinkVerifyingKey{C: make([]bw6761.G2Affine, n)}
	for i := 0; i < n; i++ {
		var aki bw6761fr.Element
		aki.Mul(&a, &k[i])
		vk.C[i].ScalarMultiplicationBase(mustBig(&aki))
	}
	vk.A.ScalarMultiplicationBase(mustBig(&a))

	return pk, vk, nil
}

// proveDummyCPLink computes the single-element proof [pi]_1 = sum_j x_j * P_j
// = [x^T M^T k]_1 = [y^T k]_1.
func proveDummyCPLink(pk cpLinkProvingKey, x []bw6761fr.Element) (cpLinkProof, error) {
	if len(pk.P) != len(x) {
		return cpLinkProof{}, fmt.Errorf("cp-link witness length mismatch: got %d, want %d", len(x), len(pk.P))
	}

	var pi bw6761.G1Affine
	pi.SetInfinity()
	for j := range x {
		var term bw6761.G1Affine
		term.ScalarMultiplication(&pk.P[j], mustBig(&x[j]))
		pi.Add(&pi, &term)
	}

	return cpLinkProof{Pi: pi}, nil
}

// verifyDummyCPLink checks the Kiltz-Wee verification equation
// prod_i e(y_i, C_i) * e(pi, -A) == 1, i.e. prod_i e(y_i, C_i) = e(pi, A).
func verifyDummyCPLink(bench cpLinkBenchmark) error {
	n := len(bench.Statement.Y)
	if len(bench.VK.C) != n {
		return fmt.Errorf("cp-link vk length mismatch: got %d, want %d", len(bench.VK.C), n)
	}

	var negA bw6761.G2Affine
	negA.Neg(&bench.VK.A)

	g1 := make([]bw6761.G1Affine, 0, n+1)
	g1 = append(g1, bench.Statement.Y...)
	g1 = append(g1, bench.Proof.Pi)

	g2 := make([]bw6761.G2Affine, 0, n+1)
	g2 = append(g2, bench.VK.C...)
	g2 = append(g2, negA)

	ok, err := bw6761.PairingCheck(g1, g2)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("cp-link pairing check failed")
	}
	return nil
}

// benchmarkDummyCPLink benchmarks a Kiltz-Wee QA-NIZK (k = 1, SXDH) that links the
// SNARK's committed witnesses `values` (here {U, SK}) to the external public points
// that live outside the circuit: one g^{values[i]} per value (i.e. g^U, and g^SK
// which equals VK = H^SK in BW6-761 G1).
//
// Witness x = (gamma, values...). Language (one row per equation):
//
//	Y[0]   = C            = gamma*G0 + sum_i values[i]*G_{i+1}   // SNARK commitment
//	Y[1+i] = g^values[i]  =           values[i]*g               // external point
//
// Proving that the same values[i] open both C and g^values[i] is exactly the
// linear-subspace statement linked by the QA-NIZK above.
func benchmarkDummyCPLink(values []bw6761fr.Element) (cpLinkBenchmark, error) {
	m := len(values)

	// Pedersen bases for the SNARK commitment: G0 (opening) + one per value.
	commitBases, err := samplePedersenLikeBases(m + 1)
	if err != nil {
		return cpLinkBenchmark{}, err
	}
	// Single base g for the external exponentiations g^{values[i]}.
	gBase, err := samplePedersenLikeBases(1)
	if err != nil {
		return cpLinkBenchmark{}, err
	}
	g := gBase[0]

	// Witness x = (gamma, values...).
	gamma, err := randomFrElement()
	if err != nil {
		return cpLinkBenchmark{}, err
	}
	x := make([]bw6761fr.Element, m+1)
	x[0] = gamma
	copy(x[1:], values)

	// Language matrix M: rows = (C, g^v0, ..., g^v_{m-1}); cols = (gamma, v0, ..., v_{m-1}).
	n := 1 + m
	t := 1 + m
	M := make([][]bw6761.G1Affine, n)
	for i := range M {
		M[i] = make([]bw6761.G1Affine, t)
		for j := range M[i] {
			M[i][j].SetInfinity()
		}
	}
	// Row 0: C = gamma*G0 + sum_i v_i*G_{i+1}.
	copy(M[0], commitBases)
	// Rows 1..m: g^{v_i} = v_i * g  -> only column (i+1) is g.
	for i := 0; i < m; i++ {
		M[1+i][1+i] = g
	}

	setupStart := time.Now()
	pk, vk, err := setupDummyCPLink(M)
	if err != nil {
		return cpLinkBenchmark{}, err
	}
	fmt.Printf("CP-Link Setup:  %v\n", time.Since(setupStart))

	// Statement y = M x (the SNARK commitment C and the external g^{values[i]} points).
	Y := make([]bw6761.G1Affine, n)
	for i := 0; i < n; i++ {
		var acc bw6761.G1Affine
		acc.SetInfinity()
		for j := 0; j < t; j++ {
			var term bw6761.G1Affine
			term.ScalarMultiplication(&M[i][j], mustBig(&x[j]))
			acc.Add(&acc, &term)
		}
		Y[i] = acc
	}

	proveTime := time.Now()
	proof, err := proveDummyCPLink(pk, x)
	if err != nil {
		return cpLinkBenchmark{}, err
	}
	fmt.Printf("CP-Link Prove:  %v\n", time.Since(proveTime))

	return cpLinkBenchmark{
		VK:        vk,
		Statement: cpLinkStatement{Y: Y},
		Proof:     proof,
	}, nil
}

func main() {
	cs, pk, vk, skBI := setup(runtime.NumCPU())
	alpha, x, srPrime := sampleProveInputs()
	pi, proof, cpLinkBench := prove(runtime.NumCPU(), skBI, alpha, x, srPrime, pk, cs)
	verify(proof, vk, pi, cpLinkBench)
}

func setup(num_cores int) (
	constraint.ConstraintSystem,
	groth16.ProvingKey,
	groth16.VerifyingKey,
	*big.Int,
) {
	runtime.GOMAXPROCS(num_cores)
	fmt.Printf("Running with GOMAXPROCS=%d (NumCPU=%d)\n", num_cores, runtime.NumCPU())

	start := time.Now()
	var circuit Circuit
	cs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Compile: %v\n", time.Since(start))
	fmt.Printf("Number of Constraints: %d\n", cs.GetNbConstraints())

	start = time.Now()
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Setup:   %v\n", time.Since(start))

	q := embeddedTed.GetEdwardsCurve().Order
	var sk bw6761fr.Element
	for {
		if _, err := sk.SetRandom(); err != nil {
			log.Fatal(err)
		}
		skBI := new(big.Int)
		sk.BigInt(skBI)
		if skBI.Cmp(&q) < 0 {
			return cs, pk, vk, skBI
		}
	}
}

func sampleProveInputs() (bw6761fr.Element, [N + 2]bw6761fr.Element, [N + 2]bw6761fr.Element) {
	var alpha bw6761fr.Element
	var x [N + 2]bw6761fr.Element
	var srPrime [N + 2]bw6761fr.Element

	_, err := alpha.SetRandom()
	if err != nil {
		log.Fatal(err)
	}
	for i := 0; i < N+2; i++ {
		if _, err := x[i].SetRandom(); err != nil {
			log.Fatal(err)
		}
		if _, err := srPrime[i].SetRandom(); err != nil {
			log.Fatal(err)
		}
	}

	return alpha, x, srPrime
}

func parallelize(length int, fn func(start, end, worker int)) int {
	if length == 0 {
		return 0
	}

	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		workers = 1
	}
	if workers > length {
		workers = length
	}
	if workers == 1 {
		fn(0, length, 0)
		return 1
	}

	chunkSize := (length + workers - 1) / workers
	var wg sync.WaitGroup

	for worker, start := 0, 0; start < length; worker, start = worker+1, start+chunkSize {
		end := start + chunkSize
		if end > length {
			end = length
		}

		wg.Add(1)
		go func(worker, start, end int) {
			defer wg.Done()
			fn(start, end, worker)
		}(worker, start, end)
	}

	wg.Wait()
	return workers
}

// lagrangeCoefficients returns the Lagrange basis coefficients evaluated at alpha
// for the interpolation domain defined by points.
func lagrangeCoefficients(alpha bw6761fr.Element, points [N + 2]bw6761fr.Element) ([N + 2]bw6761fr.Element, error) {
	var coeffs [N + 2]bw6761fr.Element
	products := make([]bw6761fr.Element, len(points))
	alphaDiffs := make([]bw6761fr.Element, len(points))
	alphaPoint := -1
	alphaPoints := make([]int, len(points))
	for i := range alphaPoints {
		alphaPoints[i] = -1
	}
	var firstErr error
	var errOnce sync.Once

	workerCount := parallelize(len(points), func(start, end, worker int) {
		localAlphaPoint := -1
		for i := start; i < end; i++ {
			products[i].SetOne()
			alphaDiffs[i].Sub(&alpha, &points[i])
			if alphaDiffs[i].IsZero() {
				localAlphaPoint = i
			}

			for j := range points {
				if i == j {
					continue
				}

				var diff bw6761fr.Element
				diff.Sub(&points[i], &points[j])
				if diff.IsZero() {
					errOnce.Do(func() {
						firstErr = fmt.Errorf("SRPrime contains duplicate elements at indexes %d and %d", i, j)
					})
					return
				}
				products[i].Mul(&products[i], &diff)
			}
		}

		if localAlphaPoint >= 0 {
			alphaPoints[worker] = localAlphaPoint
		}
	})
	if firstErr != nil {
		return coeffs, firstErr
	}

	for _, pointIdx := range alphaPoints[:workerCount] {
		if pointIdx >= 0 {
			alphaPoint = pointIdx
			break
		}
	}

	if alphaPoint >= 0 {
		coeffs[alphaPoint].SetOne()
		return coeffs, nil
	}

	weights := bw6761fr.BatchInvert(products)
	alphaDiffInvs := bw6761fr.BatchInvert(alphaDiffs)

	scaledWeights := make([]bw6761fr.Element, len(points))
	partialSums := make([]bw6761fr.Element, workerCount)
	parallelize(len(points), func(start, end, worker int) {
		for i := start; i < end; i++ {
			scaledWeights[i].Mul(&weights[i], &alphaDiffInvs[i])
			partialSums[worker].Add(&partialSums[worker], &scaledWeights[i])
		}
	})

	var sum bw6761fr.Element
	for i := range partialSums {
		sum.Add(&sum, &partialSums[i])
	}
	if sum.IsZero() {
		return coeffs, fmt.Errorf("failed to evaluate Lagrange coefficients: barycentric denominator is zero")
	}

	var sumInv bw6761fr.Element
	sumInv.Inverse(&sum)
	parallelize(len(points), func(start, end, worker int) {
		for i := start; i < end; i++ {
			coeffs[i].Mul(&scaledWeights[i], &sumInv)
		}
	})

	return coeffs, nil
}

func prove(
	num_cores int,
	skBI *big.Int,
	alpha bw6761fr.Element,
	x [N + 2]bw6761fr.Element,
	srPrime [N + 2]bw6761fr.Element,
	pk groth16.ProvingKey,
	cs constraint.ConstraintSystem,
) (witness.Witness, groth16.Proof, cpLinkBenchmark) {
	runtime.GOMAXPROCS(num_cores)
	start := time.Now()

	var w Circuit
	w.SK = skBI

	l, err := lagrangeCoefficients(alpha, srPrime)
	if err != nil {
		log.Fatal(err)
	}

	var tempU bw6761fr.Element
	tempU.SetZero()

	// Host side Poseidon2
	f := poseidon2.NewPermutation(2, 8, 50)
	var skFr bw6761fr.Element
	skFr.SetBigInt(skBI)
	skFrBytes := skFr.Bytes()
	hasher := hash.NewMerkleDamgardHasher(f, skFrBytes[:])

	for i := 0; i < N+2; i++ {
		w.X[i] = mustBig(&x[i])
		w.L[i] = mustBig(&l[i])
		w.SRPrime[i] = mustBig(&srPrime[i])

		// Poseidon2(SK, SRPrime[i])
		srPrimeBytes := srPrime[i].Bytes()

		hasher.Write(srPrimeBytes[:])
		hiBytes := hasher.Sum(nil)
		var hi bw6761fr.Element
		hi.SetBytes(hiBytes)

		var cti bw6761fr.Element
		cti.Add(&x[i], &hi)
		w.CT[i] = mustBig(&cti)

		var prod bw6761fr.Element
		prod.Mul(&x[i], &l[i])
		tempU.Add(&tempU, &prod)
	}
	w.U = mustBig(&tempU)

	witness, err := frontend.NewWitness(&w, ecc.BW6_761.ScalarField())
	if err != nil {
		log.Fatal(err)
	}
	pi, err := witness.Public()
	if err != nil {
		log.Fatal(err)
	}

	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Prove:   %v\n", time.Since(start))

	// Run the dummy CP-Link proof generation to benchmark its costs.
	// In a real implementation, this would be replaced with an actual LegoGro16 proof that links the same witness.
	// The committed witnesses linked here are {U, SK}: SK is included so that VK == H^SK
	// can be proven outside the SNARK via CP-Link instead of inside the circuit.
	cpLinkBench, err := benchmarkDummyCPLink([]bw6761fr.Element{tempU, skFr})
	if err != nil {
		log.Fatal(err)
	}

	return pi, proof, cpLinkBench
}

func verify(
	proof groth16.Proof,
	vk groth16.VerifyingKey,
	pi witness.Witness,
	cpLinkBench cpLinkBenchmark,
) {
	startVerify := time.Now()
	if err := groth16.Verify(proof, vk, pi); err != nil {
		log.Fatal("verify failed: ", err)
	}
	fmt.Printf("Verify:  %v\n", time.Since(startVerify))

	startCPLinkVerify := time.Now()
	// Run the dummy CP-Link verification to benchmark its costs.
	if err := verifyDummyCPLink(cpLinkBench); err != nil {
		log.Fatal("cp-link verify failed: ", err)
	}
	fmt.Printf("CP-Link Verify: %v\n", time.Since(startCPLinkVerify))
	fmt.Println("OK: proof verified on BW6-761")
}
