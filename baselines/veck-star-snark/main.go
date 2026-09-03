package main

import (
	"fmt"
	"log"
	"math/big"
	"runtime"
	"time"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	frbls "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	frbw "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	mimcbw "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"

	bls377 "github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
)

// Circuit encodes:
//
//	VK = H0^SK
//	For i in [0..N-1]:
//	  CTP[i] = H[i]^SK + g^X[i]      (group law on BLS12-377 G1)
//	  CT[i]  = X[i] + MiMC(SK, i)    (addition in circuit field)
//
// Plus: range checks 0 <= SK, X[i] < r_BLS12-377.
type Circuit struct {
	// Public inputs
	H0  bls377.G1Affine      `gnark:",public"`
	VK  bls377.G1Affine      `gnark:",public"`
	H   [N]bls377.G1Affine   `gnark:",public"`
	CTP [N]bls377.G1Affine   `gnark:",public"` // ct'_i
	CT  [N]frontend.Variable `gnark:",public"` // ct_i

	// Witnesses
	SK frontend.Variable
	X  [N]frontend.Variable
}

// rangeCheckFr377 enforces 0 <= v <= r-1 where r is the BLS12-377 scalar modulus.
// It (1) constrains v to n bits (nbits = bitlen(r-1)) and (2) proves v <= r-1
// using an MSB-first lexicographic compare against the constant (r-1).
func rangeCheckFr377(api frontend.API, v frontend.Variable) error {
	// Compute (r - 1) as a big.Int from the field itself: (-1 mod r) = r - 1.
	var minusOne frbls.Element
	minusOne.Sub(new(frbls.Element), new(frbls.Element).SetOne()) // 0 - 1 = -1 ≡ r-1 mod r

	var bound big.Int // r - 1
	minusOne.BigInt(&bound)
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
	curve, err := bls377.NewCurve(api)
	if err != nil {
		return err
	}

	// ---- Range/canonicality checks for SK and all X[i]
	if err := rangeCheckFr377(api, c.SK); err != nil {
		return err
	}
	for i := 0; i < N; i++ {
		if err := rangeCheckFr377(api, c.X[i]); err != nil {
			return err
		}
	}

	// vk = H0^SK
	var vkCalc bls377.G1Affine
	vkCalc.ScalarMul(api, c.H0, c.SK)
	curve.AssertIsEqual(&vkCalc, &c.VK)

	// MiMC over the circuit field (Fr(BW6-761)).
	mh, err := mimc.New(api)
	if err != nil {
		return err
	}

	for i := 0; i < N; i++ {
		// ct'_i = h_i^sk + g^x_i
		var t1 bls377.G1Affine
		t1.ScalarMul(api, c.H[i], c.SK) // variable-base * secret scalar

		var t2 bls377.G1Affine
		t2.ScalarMulBase(api, c.X[i]) // fixed-base * x_i

		sum := curve.Add(&t1, &t2)
		curve.AssertIsEqual(sum, &c.CTP[i])

		// ct_i = x_i + MiMC(sk, i)
		mh.Reset()
		mh.Write(c.SK, i)
		hi := mh.Sum()
		api.AssertIsEqual(c.CT[i], api.Add(c.X[i], hi))
	}
	return nil
}

func mustBig(n *frbls.Element) *big.Int {
	var bi big.Int
	n.BigInt(&bi)
	return &bi
}

func main() {
	parseBenchFlags()
	cs, pk, vk, skBI := setup(runtime.NumCPU())
	pi, proof := prove(skBI, pk, cs)
	verify(proof, vk, pi, cs)
	writeBenchRow(cs.GetNbConstraints(), pk)
}

func setup(num_cores int) (
	constraint.ConstraintSystem,
	groth16.ProvingKey,
	groth16.VerifyingKey,
	*big.Int,
) {
	runtime.GOMAXPROCS(num_cores)
	// make sure we time a single core unless you override with env
	fmt.Printf("Running with GOMAXPROCS=%d (NumCPU=%d)\n", num_cores, runtime.NumCPU())

	// ---- 1) build circuit
	start := time.Now()
	var circuit Circuit
	cs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		log.Fatal(err)
	}
	metrics.compile = time.Since(start)
	fmt.Printf("Compile: %v (field bits=%d)\n", metrics.compile, cs.Field().BitLen())

	// ---- 2) setup
	start = time.Now()
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		log.Fatal(err)
	}
	metrics.setup = time.Since(start)
	fmt.Printf("Setup:   %v\n", metrics.setup)

	// ---- 3) sample inputs (host side), compute publics
	// Secret key sk in Fr(BLS12-377)
	var skBLS frbls.Element
	if _, err := skBLS.SetRandom(); err != nil {
		log.Fatal(err)
	}
	skBI := mustBig(&skBLS)

	return cs, pk, vk, skBI
}

func prove(
	skBI *big.Int,
	pk groth16.ProvingKey,
	cs constraint.ConstraintSystem,
) (witness.Witness, groth16.Proof) {
	start := time.Now()
	// Random base h0 and vk = h0^sk
	var alpha frbls.Element
	if _, err := alpha.SetRandom(); err != nil {
		log.Fatal(err)
	}
	var H0 bls12377.G1Affine
	H0.ScalarMultiplicationBase(mustBig(&alpha))

	var VK bls12377.G1Affine
	VK.ScalarMultiplication(&H0, skBI)

	// MiMC host hasher over Fr(BW6-761)
	mh := mimcbw.NewMiMC()

	// Fill arrays
	var HNative [N]bls12377.G1Affine
	var CTP [N]bls12377.G1Affine
	var Xbig [N]*big.Int
	var CT [N]*big.Int

	for i := 0; i < N; i++ {
		// x_i in Fr(BLS12-377)
		var xi frbls.Element
		if _, err := xi.SetRandom(); err != nil {
			log.Fatal(err)
		}
		Xbig[i] = mustBig(&xi)

		// h_i = beta_i * G
		var beta frbls.Element
		if _, err := beta.SetRandom(); err != nil {
			log.Fatal(err)
		}
		HNative[i].ScalarMultiplicationBase(mustBig(&beta))

		// ct'_i = h_i^sk + g^x_i
		var t1, t2 bls12377.G1Affine
		t1.ScalarMultiplication(&HNative[i], skBI)
		t2.ScalarMultiplicationBase(Xbig[i])
		CTP[i].Add(&t1, &t2)

		// ct_i = x_i + MiMC(sk, i)  (host over Fr(BW6-761))
		var skBW frbw.Element
		skBW.SetBigInt(skBI)
		var iBW frbw.Element
		iBW.SetBigInt(big.NewInt(int64(i)))

		mh.Reset()
		_, _ = mh.Write(skBW.Marshal())
		_, _ = mh.Write(iBW.Marshal())
		sumBytes := mh.Sum(nil)
		var hSum frbw.Element
		hSum.SetBytes(sumBytes)

		var xiBW frbw.Element
		xiBW.SetBigInt(Xbig[i])

		var cti frbw.Element
		cti.Add(&xiBW, &hSum)
		var ctiBI big.Int
		cti.BigInt(&ctiBI)
		CT[i] = new(big.Int).Set(&ctiBI)
	}

	var w Circuit
	w.H0.Assign(&H0)
	w.VK.Assign(&VK)
	for i := 0; i < N; i++ {
		w.H[i].Assign(&HNative[i])
		w.CTP[i].Assign(&CTP[i])
		w.CT[i] = CT[i]
		w.X[i] = Xbig[i]
	}
	w.SK = skBI

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
	metrics.prove = time.Since(start)
	fmt.Printf("Prove:   %v\n", metrics.prove)

	return pi, proof
}

func verify(
	proof groth16.Proof,
	vk groth16.VerifyingKey,
	pi witness.Witness,
	cs constraint.ConstraintSystem,
) {
	startVerify := time.Now()
	if err := groth16.Verify(proof, vk, pi); err != nil {
		log.Fatal("verify failed: ", err)
	}
	metrics.verify = time.Since(startVerify)
	fmt.Printf("Verify:  %v\n", metrics.verify)

	fmt.Printf("Constraints: %d\n", cs.GetNbConstraints())
	fmt.Println("OK: proof verified on BW6-761 with native BLS12-377 G1 arithmetic + MiMC(PRF) + range checks (< r_377).")
}
