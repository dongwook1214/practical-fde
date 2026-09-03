use crate::Error;
use crate::commit::kzg::{Kzg, Powers};
use crate::divide::divide_dense_poly_fast;
use ark_ec::pairing::Pairing;
use ark_ff::FftField;
use ark_poly::DenseUVPolynomial;
use ark_poly::univariate::{DensePolynomial, SparsePolynomial};
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain, Polynomial};
use ark_std::Zero;
use ark_std::collections::{HashMap, HashSet};
use ark_std::rand::Rng;

pub fn index_map<S: FftField>(domain: GeneralEvaluationDomain<S>) -> HashMap<S, usize> {
    domain.elements().enumerate().map(|(i, e)| (e, i)).collect()
}

pub fn subset_indices<S: FftField>(
    index_map: &HashMap<S, usize>,
    subdomain: &GeneralEvaluationDomain<S>,
) -> Vec<usize> {
    subdomain
        .elements()
        .map(|e| *index_map.get(&e).unwrap())
        .collect()
}

pub fn subset_evals<S: FftField>(
    evaluations: &Evaluations<S>,
    indices: &[usize],
    subdomain: GeneralEvaluationDomain<S>,
) -> Evaluations<S> {
    debug_assert!(evaluations.domain().size() >= subdomain.size());
    let mut subset_evals = Vec::with_capacity(indices.len());
    for &index in indices {
        subset_evals.push(evaluations.evals[index]);
    }
    Evaluations::from_vec_and_domain(subset_evals, subdomain)
}

// Test function
pub fn random_subset_indices<R: Rng>(
    evals_len: usize,
    subset_size: usize,
    rng: &mut R,
) -> Vec<usize> {
    let mut index_set = HashSet::<usize>::with_capacity(subset_size);
    while index_set.len() < subset_size {
        index_set.insert(rng.gen_range(0..evals_len));
    }

    let mut indices = index_set.into_iter().collect::<Vec<_>>();
    indices.sort_unstable();
    indices
}

pub fn to_vanishing_poly<S: FftField>(
    indices: Vec<usize>,
    domain: GeneralEvaluationDomain<S>,
) -> SparsePolynomial<S> {
    let mut poly = SparsePolynomial::from_coefficients_vec(vec![(0, S::one())]);
    for i in indices {
        let root = domain.element(i);
        let x_minus_root =
            SparsePolynomial::from_coefficients_vec(vec![(0, S::zero() - root), (1, S::one())]);
        poly = poly.mul(&x_minus_root);
    }
    poly
}

pub fn compute_beta(size_sr: usize, lambda: usize) -> f64 {
    let lower_power = (lambda as f64) / (size_sr as f64);
    let upper_power = (lambda as f64) / ((size_sr - 1) as f64);
    let two_lower_power = 2f64.powf(lower_power);
    let two_upper_power = 2f64.powf(upper_power);
    let beta1 = two_lower_power / (2f64 - two_lower_power);
    let beta2 = two_upper_power / (2f64 - two_upper_power);
    (beta1 + beta2) / 2f64
}

pub fn interpolate_indices<S: FftField>(
    evaluations: &Evaluations<S>,
    indices: &[usize],
) -> DensePolynomial<S> {
    let domain = evaluations.domain();
    let points = indices
        .iter()
        .map(|&index| domain.element(index))
        .collect::<Vec<_>>();
    let values = indices
        .iter()
        .map(|&index| evaluations.evals[index])
        .collect::<Vec<_>>();
    interpolate_points(&points, &values)
}

pub fn interpolate_points<S: FftField>(points: &[S], values: &[S]) -> DensePolynomial<S> {
    assert_eq!(points.len(), values.len());
    assert!(!points.is_empty());

    let vanishing = DensePolynomial::from(to_vanishing_poly_from_points(points));
    let mut result = DensePolynomial::zero();

    for (&point, &value) in points.iter().zip(values.iter()) {
        let divisor = DensePolynomial::from_coefficients_slice(&[-point, S::one()]);
        let numerator = &vanishing / &divisor;
        debug_assert_eq!(&numerator * &divisor, vanishing);
        let denominator = numerator.evaluate(&point);
        let scale = value * denominator.inverse().unwrap();
        let scaled = DensePolynomial::from_coefficients_vec(
            numerator
                .coeffs
                .iter()
                .map(|coeff| *coeff * scale)
                .collect(),
        );
        result += &scaled;
    }

    result
}

pub fn subset_quotient<S: FftField>(
    full_poly: &DensePolynomial<S>,
    subset_poly: &DensePolynomial<S>,
    subdomain: GeneralEvaluationDomain<S>,
) -> Result<DensePolynomial<S>, Error> {
    let vanishing_poly = DensePolynomial::from(subdomain.vanishing_polynomial());
    subset_quotient_with_vanishing_poly(full_poly, subset_poly, &vanishing_poly)
}

pub fn subset_quotient_with_vanishing_poly<S: FftField>(
    full_poly: &DensePolynomial<S>,
    subset_poly: &DensePolynomial<S>,
    vanishing_poly: &DensePolynomial<S>,
) -> Result<DensePolynomial<S>, Error> {
    let difference = full_poly - subset_poly;
    let (quotient, _) = divide_dense_poly_fast(&difference, vanishing_poly)?;
    // if &quotient * vanishing_poly != difference {
    //     return Err(Error::NonZeroSubsetRemainder);
    // }
    Ok(quotient)
}

pub fn verify_subset_relation<C: Pairing>(
    full_commitment: C::G1,
    subset_commitment: C::G1,
    quotient_commitment: C::G1,
    subdomain: GeneralEvaluationDomain<C::ScalarField>,
    powers: &Powers<C>,
) -> bool {
    let vanishing_poly = DensePolynomial::from(subdomain.vanishing_polynomial());
    let vanishing_commitment = powers.commit_g2(&vanishing_poly);
    verify_subset_relation_with_vanishing_commitment::<C>(
        full_commitment,
        subset_commitment,
        quotient_commitment,
        vanishing_commitment,
    )
}

pub fn verify_subset_relation_with_vanishing_poly<C: Pairing>(
    full_commitment: C::G1,
    subset_commitment: C::G1,
    quotient_commitment: C::G1,
    vanishing_poly: &DensePolynomial<C::ScalarField>,
    powers: &Powers<C>,
) -> bool {
    let vanishing_commitment = powers.commit_g2(vanishing_poly);
    verify_subset_relation_with_vanishing_commitment::<C>(
        full_commitment,
        subset_commitment,
        quotient_commitment,
        vanishing_commitment,
    )
}

pub fn verify_subset_relation_with_vanishing_commitment<C: Pairing>(
    full_commitment: C::G1,
    subset_commitment: C::G1,
    quotient_commitment: C::G1,
    vanishing_commitment: C::G2,
) -> bool {
    Kzg::<C>::pairing_check(
        full_commitment - subset_commitment,
        quotient_commitment,
        vanishing_commitment,
    )
}

fn to_vanishing_poly_from_points<S: FftField>(points: &[S]) -> SparsePolynomial<S> {
    let mut poly = SparsePolynomial::from_coefficients_vec(vec![(0, S::one())]);
    for &point in points {
        let x_minus_root =
            SparsePolynomial::from_coefficients_vec(vec![(0, S::zero() - point), (1, S::one())]);
        poly = poly.mul(&x_minus_root);
    }
    poly
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::commit::kzg::Powers;
    use ark_bw6_761::BW6_761;
    use ark_ff::UniformRand;
    use ark_poly::Polynomial;
    use ark_std::test_rng;

    type Scalar = <BW6_761 as Pairing>::ScalarField;

    #[test]
    fn subset_relation_holds() {
        let rng = &mut test_rng();
        let domain_size = 16usize;
        let subset_size = 4usize;

        let tau = Scalar::rand(rng);
        let powers = Powers::<BW6_761>::unsafe_setup(tau, domain_size + 1);

        let domain = GeneralEvaluationDomain::new(domain_size).unwrap();
        let subdomain = GeneralEvaluationDomain::new(subset_size).unwrap();

        let data: Vec<Scalar> = (0..domain_size).map(|_| Scalar::rand(rng)).collect();
        let evaluations = Evaluations::from_vec_and_domain(data, domain);
        let full_poly = evaluations.interpolate_by_ref();

        let indices = subset_indices(&index_map(domain), &subdomain);
        let subset_evaluations = subset_evals(&evaluations, &indices, subdomain);
        let subset_poly = subset_evaluations.interpolate_by_ref();
        let quotient = subset_quotient(&full_poly, &subset_poly, subdomain).unwrap();

        let full_commitment = powers.commit_g1(&full_poly);
        let subset_commitment = powers.commit_g1(&subset_poly);
        let quotient_commitment = powers.commit_g1(&quotient);

        assert!(verify_subset_relation::<BW6_761>(
            full_commitment,
            subset_commitment,
            quotient_commitment,
            subdomain,
            &powers,
        ));
    }

    #[test]
    fn subset_opening_verifies() {
        let rng = &mut test_rng();
        let domain_size = 16usize;
        let subset_size = 4usize;

        let tau = Scalar::rand(rng);
        let powers = Powers::<BW6_761>::unsafe_setup(tau, domain_size + 1);

        let domain = GeneralEvaluationDomain::new(domain_size).unwrap();
        let subdomain = GeneralEvaluationDomain::new(subset_size).unwrap();

        let data: Vec<Scalar> = (0..domain_size).map(|_| Scalar::rand(rng)).collect();
        let evaluations = Evaluations::from_vec_and_domain(data, domain);
        let indices = subset_indices(&index_map(domain), &subdomain);
        let subset_evaluations = subset_evals(&evaluations, &indices, subdomain);
        let subset_poly = subset_evaluations.interpolate_by_ref();

        let point = Scalar::rand(rng);
        let value = subset_poly.evaluate(&point);
        let commitment = powers.commit_g1(&subset_poly).into();
        let proof = Kzg::<BW6_761>::proof(&subset_poly, point, value, &powers);

        assert!(Kzg::<BW6_761>::verify_scalar(
            proof, commitment, point, value, &powers,
        ));
    }

    #[test]
    fn random_subset_indices_are_unique() {
        let rng = &mut test_rng();
        let indices = random_subset_indices(64, 16, rng);
        let set = indices.iter().copied().collect::<HashSet<_>>();
        assert_eq!(indices.len(), 16);
        assert_eq!(set.len(), 16);
    }

    #[test]
    fn test_compute_beta() {
        for i in 8..=16 {
            let size_sr = 1 << i;
            let beta = compute_beta(size_sr, 128);
            let denominator = (beta * 2f64 / (beta + 1f64)).log2();
            let sr = (128f64 / denominator).ceil() as usize;
            assert_eq!(size_sr, sr);
        }
    }

    #[test]
    fn random_subset_relation_holds() {
        let rng = &mut test_rng();
        let domain_size = 32usize;
        let subset_size = 8usize;

        let tau = Scalar::rand(rng);
        let powers = Powers::<BW6_761>::unsafe_setup(tau, domain_size + 1);
        let domain = GeneralEvaluationDomain::new(domain_size).unwrap();
        let data: Vec<Scalar> = (0..domain_size).map(|_| Scalar::rand(rng)).collect();
        let evaluations = Evaluations::from_vec_and_domain(data, domain);
        let full_poly = evaluations.interpolate_by_ref();

        let indices = random_subset_indices(domain_size, subset_size, rng);
        let subset_poly = interpolate_indices(&evaluations, &indices);
        let vanishing_poly = DensePolynomial::from(to_vanishing_poly(indices, domain));
        let quotient =
            subset_quotient_with_vanishing_poly(&full_poly, &subset_poly, &vanishing_poly).unwrap();

        assert!(verify_subset_relation_with_vanishing_poly::<BW6_761>(
            powers.commit_g1(&full_poly),
            powers.commit_g1(&subset_poly),
            powers.commit_g1(&quotient),
            &vanishing_poly,
            &powers,
        ));
    }
}
