//! Reed--Solomon expansion of the file.
//!
//! All coded FDE variants (VECK+, VECK*, ours) send a codeword of
//! `m = ceil(beta * ell)` symbols instead of the `ell` file symbols.  Since the
//! file lives on the multiplicative subgroup `D_ell` and the codeword on the
//! larger subgroup `D_m'` (`m' = 2^ceil(log2 m)`), and `D_ell <= D_m'`, the code
//! is a systematic Reed--Solomon code: interpolating the file gives the degree
//! `< ell` message polynomial `phi`, and evaluating `phi` over `D_m'` produces
//! the codeword, whose every `(m'/ell)`-th entry is a file symbol.
//!
//! Both halves are FFTs, so this is exactly what `Evaluations::interpolate` and
//! `DensePolynomial::evaluate_over_domain` do; we time them as the `encode`
//! stage.

use ark_ff::FftField;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain};
use std::time::{Duration, Instant};

pub struct Encoded<F: FftField> {
    /// Message polynomial, degree `< ell`.
    pub poly: DensePolynomial<F>,
    /// Evaluation domain the codeword lives on (size `code_len`).
    pub code_domain: GeneralEvaluationDomain<F>,
    /// The codeword itself, `code_len` symbols.
    pub codeword: Evaluations<F>,
}

/// Interpolate `file` over `D_{file.len()}` and expand it to `code_len` symbols.
///
/// `code_len` must be a power of two and at least `file.len()`.  When the two
/// coincide the expansion is the identity and only the interpolation is timed,
/// which is the uncoded (base VECK) case.
pub fn encode<F: FftField>(file: &[F], code_len: usize) -> (Encoded<F>, Duration) {
    assert!(code_len >= file.len(), "codeword shorter than the file");
    assert!(code_len.is_power_of_two(), "codeword length must be a power of two");

    let started = Instant::now();

    let file_domain =
        GeneralEvaluationDomain::<F>::new(file.len()).expect("valid file evaluation domain");
    let poly = Evaluations::from_vec_and_domain(file.to_vec(), file_domain).interpolate();

    let code_domain =
        GeneralEvaluationDomain::<F>::new(code_len).expect("valid codeword evaluation domain");
    let codeword = if code_len == file.len() {
        Evaluations::from_vec_and_domain(file.to_vec(), code_domain)
    } else {
        poly.evaluate_over_domain_by_ref(code_domain)
    };

    let elapsed = started.elapsed();

    (
        Encoded {
            poly,
            code_domain,
            codeword,
        },
        elapsed,
    )
}

/// Length of the codeword actually transmitted, `m = ceil(beta * ell)`, and the
/// power-of-two evaluation domain `m'` it is embedded in.
pub fn code_lengths(ell: usize, beta: f64) -> (usize, usize) {
    let m = (ell as f64 * beta).ceil() as usize;
    let m = m.max(ell);
    (m, m.next_power_of_two().max(ell))
}
