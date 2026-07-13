use ark_ff::FftField;
use ark_poly::DenseUVPolynomial;
use ark_poly::Polynomial;
use ark_poly::univariate::DensePolynomial;
use ark_std::Zero;

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

fn divide_by_low_degree_blocked<F: FftField>(
    dividend: &DensePolynomial<F>,
    divisor: &DensePolynomial<F>,
    quotient_len: usize,
) -> (DensePolynomial<F>, DensePolynomial<F>) {
    const BLOCK_SIZE: usize = 8192;

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

    (quotient, remainder)
}

// Compute the Euclidean quotient via reversed polynomials and Newton inversion:
// Q^rev = A^rev * (B^rev)^(-1) mod x^(deg(A)-deg(B)+1).
pub fn divide_dense_poly_fast<F: FftField>(
    dividend: &DensePolynomial<F>,
    divisor: &DensePolynomial<F>,
) -> (DensePolynomial<F>, DensePolynomial<F>) {
    if divisor.is_zero() {
        panic!("division by zero polynomial");
    }

    if dividend.is_zero() {
        return (DensePolynomial::zero(), DensePolynomial::zero());
    }

    if dividend.degree() < divisor.degree() {
        return (DensePolynomial::zero(), dividend.clone());
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
        return (quotient, DensePolynomial::zero());
    }

    if is_xn_minus_one(divisor) {
        return divide_by_xn_minus_one(dividend, divisor.degree());
    }

    let quotient_len = dividend.degree() - divisor.degree() + 1;
    if divisor.degree() <= 650 && quotient_len > 8192 {
        return divide_by_low_degree_blocked(dividend, divisor, quotient_len);
    }

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

    (quotient, remainder)
}