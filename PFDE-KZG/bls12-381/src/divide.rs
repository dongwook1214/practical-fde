//! Euclidean division of dense polynomials.
//!
//! `(phi - f_S) / Z_S` is on the prover's critical path, so this module keeps two
//! strategies and dispatches between them:
//!
//! * [`divide_newton`] reverses both polynomials and inverts the divisor as a
//!   power series (`Q^rev = A^rev * (B^rev)^-1 mod x^(deg A - deg B + 1)`).
//! * [`divide_blocked`] does the same but slices the quotient into blocks, so the
//!   series inversion is only computed to `BLOCK_SIZE` precision instead of the
//!   full quotient length.  That wins when the divisor is small relative to the
//!   dividend, which is exactly the sampling case (`deg Z_S = R << ell`).
//!
//! [`LOW_DEGREE_DIVISOR_LIMIT`] is the crossover.  It is hardware-dependent;
//! `cargo test --release -- --ignored divide_threshold_probe --nocapture` in
//! `benchmarks/kzg` re-measures it.

use crate::Error;
use ark_ff::FftField;
use ark_poly::DenseUVPolynomial;
use ark_poly::Polynomial;
use ark_poly::univariate::DensePolynomial;
use ark_std::Zero;

/// Largest divisor degree for which the blocked strategy is used.
///
/// Measured on an Apple M3 Pro at `ell = 2^20`: the blocked path wins by 1.4x at
/// `R = 1024` and 1.35x at `R = 1280`, and loses from `R = 1536` on, because its
/// per-block tail correction is quadratic in the divisor degree while the plain
/// Newton path is not.  Anything in `[1024, 1280]` behaves identically for the
/// sample counts the paper uses; re-measure with
/// `cargo test --release -- --ignored divide_threshold_probe --nocapture` in
/// `benchmarks/kzg` before trusting it on other hardware.
pub const LOW_DEGREE_DIVISOR_LIMIT: usize = 1280;

/// Minimum quotient length before blocking is worth its bookkeeping.
pub const BLOCKING_MIN_QUOTIENT_LEN: usize = 8192;

/// Precision the divisor's series inverse is computed to in the blocked path.
const BLOCK_SIZE: usize = 8192;

fn truncate_poly<F: FftField>(poly: &DensePolynomial<F>, len: usize) -> DensePolynomial<F> {
    DensePolynomial::from_coefficients_vec(poly.coeffs.iter().cloned().take(len).collect())
}

fn reverse_poly<F: FftField>(poly: &DensePolynomial<F>, len: usize) -> DensePolynomial<F> {
    DensePolynomial::from_coefficients_vec(poly.coeffs.iter().cloned().rev().take(len).collect())
}

fn reverse_coeffs<F: FftField>(poly: &DensePolynomial<F>, len: usize) -> Vec<F> {
    poly.coeffs.iter().cloned().rev().take(len).collect()
}

fn is_xn_minus_one<F: FftField>(poly: &DensePolynomial<F>) -> bool {
    let degree = poly.degree();
    degree > 0
        && poly.coeffs[0] == -F::one()
        && poly.coeffs[degree] == F::one()
        && poly.coeffs[1..degree].iter().all(|coeff| coeff.is_zero())
}

fn divide_by_xn_minus_one<F: FftField>(
    dividend: &DensePolynomial<F>,
    n: usize,
) -> (DensePolynomial<F>, DensePolynomial<F>) {
    if dividend.coeffs.len() < n + 1 {
        return (DensePolynomial::zero(), dividend.clone());
    }

    let mut quotient_vec = dividend.coeffs[n..].to_vec();
    for i in (0..quotient_vec.len()).rev() {
        if i + n < quotient_vec.len() {
            let folded = quotient_vec[i + n];
            quotient_vec[i] += folded;
        }
    }

    let mut remainder_vec = dividend.coeffs[..n].to_vec();
    for (slot, coeff) in remainder_vec.iter_mut().zip(quotient_vec.iter()) {
        *slot += coeff;
    }

    (
        DensePolynomial::from_coefficients_vec(quotient_vec),
        DensePolynomial::from_coefficients_vec(remainder_vec),
    )
}

fn invert_series_mod_xn<F: FftField>(
    poly: &DensePolynomial<F>,
    precision: usize,
) -> DensePolynomial<F> {
    let two = F::one() + F::one();
    let mut inverse =
        DensePolynomial::from_coefficients_vec(vec![poly.coeffs[0].inverse().unwrap()]);
    let mut current_precision = 1usize;

    while current_precision < precision {
        let next_precision = (current_precision * 2).min(precision);
        let poly_truncated = truncate_poly(poly, next_precision);
        let prod = truncate_poly(&(&poly_truncated * &inverse), next_precision);

        let mut correction = vec![F::zero(); next_precision];
        correction[0] = two;
        for (i, coeff) in prod.coeffs.iter().enumerate() {
            correction[i] -= coeff;
        }

        let correction = DensePolynomial::from_coefficients_vec(correction);
        inverse = truncate_poly(&(&inverse * &correction), next_precision);
        current_precision = next_precision;
    }

    inverse
}

fn low_degree_product<F: FftField>(
    lhs: &DensePolynomial<F>,
    rhs: &DensePolynomial<F>,
    len: usize,
) -> Vec<F> {
    let mut product = vec![F::zero(); len];
    let lhs_len = lhs.coeffs.len().min(len);
    for i in 0..lhs_len {
        let lhs_coeff = lhs.coeffs[i];
        let rhs_len = rhs.coeffs.len().min(len - i);
        for j in 0..rhs_len {
            product[i + j] += lhs_coeff * rhs.coeffs[j];
        }
    }
    product
}

fn compute_remainder<F: FftField>(
    dividend: &DensePolynomial<F>,
    divisor: &DensePolynomial<F>,
    quotient: &DensePolynomial<F>,
) -> DensePolynomial<F> {
    let remainder_len = divisor.degree();
    if remainder_len == 0 {
        return DensePolynomial::zero();
    }

    let mut remainder_coeffs = dividend.coeffs[..dividend.coeffs.len().min(remainder_len)].to_vec();
    remainder_coeffs.resize(remainder_len, F::zero());

    // For the common "large dividend / small divisor" case, the remainder only
    // needs the first `divisor.degree()` coefficients of quotient * divisor.
    if remainder_len <= 4096 {
        let product_low = low_degree_product(quotient, divisor, remainder_len);
        for (rem, prod) in remainder_coeffs.iter_mut().zip(product_low) {
            *rem -= prod;
        }
        DensePolynomial::from_coefficients_vec(remainder_coeffs)
    } else {
        let product = quotient * divisor;
        dividend - &product
    }
}

/// Blocked Newton division: the divisor's series inverse is only computed to
/// `BLOCK_SIZE` precision, and the quotient is swept block by block.
pub fn divide_blocked<F: FftField>(
    dividend: &DensePolynomial<F>,
    divisor: &DensePolynomial<F>,
) -> Result<(DensePolynomial<F>, DensePolynomial<F>), Error> {
    if divisor.is_zero() {
        return Err(Error::DivisionByZeroPolynomial);
    }
    if dividend.degree() < divisor.degree() {
        return Ok((DensePolynomial::zero(), dividend.clone()));
    }
    let quotient_len = dividend.degree() - divisor.degree() + 1;

    let divisor_degree = divisor.degree();
    let block_size = BLOCK_SIZE.min(quotient_len);
    let divisor_reversed_coeffs = reverse_coeffs(divisor, divisor_degree + 1);
    let divisor_reversed = DensePolynomial::from_coefficients_vec(divisor_reversed_coeffs.clone());
    let inverse_block = invert_series_mod_xn(&divisor_reversed, block_size);
    let mut work = reverse_coeffs(dividend, quotient_len);
    work.resize(quotient_len, F::zero());

    for block_start in (0..quotient_len).step_by(block_size) {
        let len = block_size.min(quotient_len - block_start);
        let block =
            DensePolynomial::from_coefficients_vec(work[block_start..block_start + len].to_vec());
        let quotient_block = if len == block_size {
            truncate_poly(&(&block * &inverse_block), len)
        } else {
            let inverse = truncate_poly(&inverse_block, len);
            truncate_poly(&(&block * &inverse), len)
        };
        let mut quotient_coeffs = quotient_block.coeffs;
        quotient_coeffs.resize(len, F::zero());

        work[block_start..block_start + len].clone_from_slice(&quotient_coeffs);

        let tail_len = divisor_degree.min(quotient_len - block_start - len);
        for tail_offset in 0..tail_len {
            let product_index = len + tail_offset;
            let min_divisor_index = product_index - len + 1;
            let max_divisor_index = divisor_degree.min(product_index);
            let mut tail_coeff = F::zero();

            for divisor_index in min_divisor_index..=max_divisor_index {
                let quotient_index = product_index - divisor_index;
                let divisor_coeff = divisor_reversed_coeffs
                    .get(divisor_index)
                    .copied()
                    .unwrap_or_else(F::zero);
                tail_coeff += quotient_coeffs[quotient_index] * divisor_coeff;
            }

            work[block_start + product_index] -= tail_coeff;
        }
    }

    work.reverse();
    let quotient = DensePolynomial::from_coefficients_vec(work);
    let remainder = compute_remainder(dividend, divisor, &quotient);

    Ok((quotient, remainder))
}

/// Plain Newton division: invert the reversed divisor to the full quotient
/// length in one go.
pub fn divide_newton<F: FftField>(
    dividend: &DensePolynomial<F>,
    divisor: &DensePolynomial<F>,
) -> Result<(DensePolynomial<F>, DensePolynomial<F>), Error> {
    if divisor.is_zero() {
        return Err(Error::DivisionByZeroPolynomial);
    }
    if dividend.degree() < divisor.degree() {
        return Ok((DensePolynomial::zero(), dividend.clone()));
    }
    let quotient_len = dividend.degree() - divisor.degree() + 1;

    let dividend_reversed = reverse_poly(dividend, quotient_len);
    let divisor_reversed = reverse_poly(divisor, quotient_len.min(divisor.coeffs.len()));
    let divisor_reversed_inv = invert_series_mod_xn(&divisor_reversed, quotient_len);
    let quotient_reversed =
        truncate_poly(&(&dividend_reversed * &divisor_reversed_inv), quotient_len);

    let mut quotient_coeffs = quotient_reversed.coeffs;
    quotient_coeffs.resize(quotient_len, F::zero());
    quotient_coeffs.reverse();
    let quotient = DensePolynomial::from_coefficients_vec(quotient_coeffs);
    let remainder = compute_remainder(dividend, divisor, &quotient);

    Ok((quotient, remainder))
}

/// Euclidean division, dispatching to the cheapest available strategy.
pub fn divide_dense_poly_fast<F: FftField>(
    dividend: &DensePolynomial<F>,
    divisor: &DensePolynomial<F>,
) -> Result<(DensePolynomial<F>, DensePolynomial<F>), Error> {
    if divisor.is_zero() {
        return Err(Error::DivisionByZeroPolynomial);
    }

    if dividend.is_zero() {
        return Ok((DensePolynomial::zero(), DensePolynomial::zero()));
    }

    if dividend.degree() < divisor.degree() {
        return Ok((DensePolynomial::zero(), dividend.clone()));
    }

    if divisor.degree() == 0 {
        let divisor_inv = divisor.coeffs[0].inverse().unwrap();
        let quotient = DensePolynomial::from_coefficients_vec(
            dividend
                .coeffs
                .iter()
                .map(|coeff| *coeff * divisor_inv)
                .collect(),
        );
        return Ok((quotient, DensePolynomial::zero()));
    }

    if is_xn_minus_one(divisor) {
        return Ok(divide_by_xn_minus_one(dividend, divisor.degree()));
    }

    let quotient_len = dividend.degree() - divisor.degree() + 1;
    if divisor.degree() <= LOW_DEGREE_DIVISOR_LIMIT && quotient_len > BLOCKING_MIN_QUOTIENT_LEN {
        return divide_blocked(dividend, divisor);
    }

    divide_newton(dividend, divisor)
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::Bls12_381 as TestCurve;
    use ark_poly::EvaluationDomain;
    use ark_poly::GeneralEvaluationDomain;
    use ark_poly::univariate::DenseOrSparsePolynomial;
    use ark_std::test_rng;

    type Scalar = <TestCurve as ark_ec::pairing::Pairing>::ScalarField;
    type UniPoly = DensePolynomial<Scalar>;

    #[test]
    fn divide_by_vanishing_poly_test() {
        let rng = &mut test_rng();
        let domain_size = 512;
        let domain = GeneralEvaluationDomain::<Scalar>::new(domain_size).unwrap();
        let f_poly: DensePolynomial<Scalar> = UniPoly::rand(1024, rng);
        let divisor = DensePolynomial::from(domain.vanishing_polynomial());
        let (quotient, remainder) = divide_dense_poly_fast(&f_poly, &divisor).unwrap();
        assert!(!quotient.is_zero());
        assert!(remainder.is_zero() || remainder.degree() < divisor.degree());
    }

    #[test]
    fn divide_by_random_poly_test() {
        let rng = &mut test_rng();
        let divisor: DensePolynomial<Scalar> = UniPoly::rand(512, rng);
        let f_poly: DensePolynomial<Scalar> = UniPoly::rand(1024, rng);
        let (quotient, remainder) = divide_dense_poly_fast(&f_poly, &divisor).unwrap();
        assert!(!quotient.is_zero());
        assert!(remainder.is_zero() || remainder.degree() < divisor.degree());
    }

    #[test]
    fn divide_by_low_degree_blocked_matches_identity() {
        let rng = &mut test_rng();
        for divisor_degree in [256, 512, 1024] {
            let divisor: DensePolynomial<Scalar> = UniPoly::rand(divisor_degree, rng);
            let f_poly: DensePolynomial<Scalar> = UniPoly::rand(16 * 1024, rng);
            let (quotient, remainder) = divide_dense_poly_fast(&f_poly, &divisor).unwrap();
            let product = &quotient * &divisor;
            assert_eq!(&product + &remainder, f_poly);
            assert!(remainder.is_zero() || remainder.degree() < divisor.degree());
        }
    }

    #[test]
    fn both_strategies_agree() {
        // The dispatch threshold must never change the answer, only the cost.
        let rng = &mut test_rng();
        for divisor_degree in [64, 256, 650, 651, 1024, 2048] {
            let divisor: DensePolynomial<Scalar> = UniPoly::rand(divisor_degree, rng);
            let f_poly: DensePolynomial<Scalar> = UniPoly::rand(64 * 1024, rng);
            let blocked = divide_blocked(&f_poly, &divisor).unwrap();
            let newton = divide_newton(&f_poly, &divisor).unwrap();
            assert_eq!(blocked.0, newton.0, "quotients differ at degree {divisor_degree}");
            assert_eq!(blocked.1, newton.1, "remainders differ at degree {divisor_degree}");
            let product = &blocked.0 * &divisor;
            assert_eq!(&product + &blocked.1, f_poly);
        }
    }

    #[test]
    fn divide_by_constant_poly_test() {
        let rng = &mut test_rng();
        let divisor = DensePolynomial::from_coefficients_vec(vec![Scalar::from(7u64)]);
        let f_poly: DensePolynomial<Scalar> = UniPoly::rand(4096, rng);
        let (quotient, remainder) = divide_dense_poly_fast(&f_poly, &divisor).unwrap();
        let product = &quotient * &divisor;
        assert_eq!(&product + &remainder, f_poly);
        assert!(remainder.is_zero());
    }

    #[test]
    fn division_by_zero_is_an_error() {
        let f_poly = UniPoly::from_coefficients_vec(vec![Scalar::from(1u64)]);
        assert_eq!(
            divide_dense_poly_fast(&f_poly, &DensePolynomial::zero()).unwrap_err(),
            Error::DivisionByZeroPolynomial
        );
    }

    #[test]
    fn divide_by_xn_minus_one_matches_long_division() {
        let rng = &mut test_rng();
        for domain_size in [2, 3, 8, 17] {
            let divisor = DensePolynomial::from_coefficients_vec({
                let mut coeffs = vec![Scalar::zero(); domain_size + 1];
                coeffs[0] = -Scalar::from(1u64);
                coeffs[domain_size] = Scalar::from(1u64);
                coeffs
            });
            let f_poly: DensePolynomial<Scalar> = UniPoly::rand(domain_size * 5 + 3, rng);
            let (fast_quotient, fast_remainder) =
                divide_dense_poly_fast(&f_poly, &divisor).unwrap();
            let dividend_poly = DenseOrSparsePolynomial::from(&f_poly);
            let divisor_poly = DenseOrSparsePolynomial::from(&divisor);
            let (expected_quotient, expected_remainder) =
                dividend_poly.divide_with_q_and_r(&divisor_poly).unwrap();
            assert_eq!(fast_quotient, expected_quotient);
            assert_eq!(fast_remainder, expected_remainder);
        }
    }
}
