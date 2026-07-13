use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM as Msm};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_poly_commit::DenseUVPolynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;
use ark_std::{One, UniformRand, Zero};

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Powers<C: Pairing> {
    pub g1: Vec<C::G1Affine>,
    pub g2: Vec<C::G2Affine>,
}

impl<C: Pairing> Powers<C> {
    pub fn unsafe_setup(tau: C::ScalarField, range: usize) -> Self {
        let mut g1 = Vec::with_capacity(range);
        let mut g2 = Vec::with_capacity(range);
        let mut exponent = C::ScalarField::one();
        for _ in 1..=range {
            g1.push((<C::G1Affine as AffineRepr>::generator() * exponent).into_affine());
            g2.push((<C::G2Affine as AffineRepr>::generator() * exponent).into_affine());
            exponent *= tau;
        }
        Self { g1, g2 }
    }

    pub fn unsafe_setup_eip_4844(tau: C::ScalarField, range: usize) -> Self {
        let mut g1 = Vec::with_capacity(range);
        let mut g2 = Vec::with_capacity(range);
        let domain = GeneralEvaluationDomain::new(range).unwrap();
        let lagrange_evaluations = domain.evaluate_all_lagrange_coefficients(tau);
        lagrange_evaluations.into_iter().for_each(|exponent| {
            g1.push((<C::G1Affine as AffineRepr>::generator() * exponent).into_affine());
            g2.push((<C::G2Affine as AffineRepr>::generator() * exponent).into_affine());
        });

        Self { g1, g2 }
    }

    pub fn commit_scalars_g1(&self, scalars: &[C::ScalarField]) -> C::G1 {
        Msm::msm_unchecked(&self.g1[0..scalars.len()], scalars)
    }

    pub fn commit_scalars_g2(&self, scalars: &[C::ScalarField]) -> C::G2 {
        Msm::msm_unchecked(&self.g2[0..scalars.len()], scalars)
    }

    pub fn commit_g1<P: DenseUVPolynomial<C::ScalarField, Point = C::ScalarField>>(
        &self,
        poly: &P,
    ) -> C::G1 {
        self.commit_scalars_g1(poly.coeffs())
    }

    pub fn commit_g2<P: DenseUVPolynomial<C::ScalarField, Point = C::ScalarField>>(
        &self,
        poly: &P,
    ) -> C::G2 {
        self.commit_scalars_g2(poly.coeffs())
    }

    pub fn g1_tau(&self) -> C::G1Affine {
        self.g1[1]
    }

    pub fn g2_tau(&self) -> C::G2Affine {
        self.g2[1]
    }
}

pub struct Kzg<C: Pairing>(PhantomData<C>);

impl<C: Pairing> Kzg<C> {
    pub fn witness(
        poly: &DensePolynomial<C::ScalarField>,
        point: C::ScalarField,
    ) -> DensePolynomial<C::ScalarField> {
        let divisor = DensePolynomial::from_coefficients_slice(&[-point, C::ScalarField::one()]);
        poly / &divisor
    }

    pub fn proof(
        poly: &DensePolynomial<C::ScalarField>,
        point: C::ScalarField,
        value: C::ScalarField,
        powers: &Powers<C>,
    ) -> C::G1Affine {
        let numerator = poly + &DensePolynomial::from_coefficients_slice(&[-value]);
        let quotient = Self::witness(&numerator, point);
        powers.commit_g1(&quotient).into()
    }

    pub fn verify_scalar(
        proof: C::G1Affine,
        commitment: C::G1Affine,
        point: C::ScalarField,
        value: C::ScalarField,
        powers: &Powers<C>,
    ) -> bool {
        let point_g2 = C::G2Affine::generator() * point;
        let value_g1 = C::G1Affine::generator() * value;
        Self::verify(proof, commitment, point_g2, value_g1, powers)
    }

    pub fn verify(
        proof: C::G1Affine,
        commitment: C::G1Affine,
        point: C::G2,
        value: C::G1,
        powers: &Powers<C>,
    ) -> bool {
        let com_over_g_value = commitment.into_group() - value;
        let g_tau_over_g_point = powers.g2_tau().into_group() - point;
        Self::pairing_check(com_over_g_value, proof.into_group(), g_tau_over_g_point)
    }

    pub fn pairing_check(lhs_g1: C::G1, rhs_g1: C::G1, rhs_g2: C::G2) -> bool {
        let lhs = C::pairing(lhs_g1, C::G2Affine::generator());
        let rhs = C::pairing(rhs_g1, rhs_g2);
        lhs == rhs
    }

    pub fn batch_verify<R: Rng>(
        proofs: &[C::G1Affine],
        commitments: &[C::G1Affine],
        points: &[C::ScalarField],
        values: &[C::ScalarField],
        powers: &Powers<C>,
        rng: &mut R,
    ) -> bool {
        let mut total_c = <C::G1>::zero();
        let mut total_w = <C::G1>::zero();

        let mut randomizer = C::ScalarField::one();
        let mut g_multiplier = C::ScalarField::zero();
        let gamma_g_multiplier = C::ScalarField::zero();
        for (((c, &z), v), &w) in commitments.iter().zip(points).zip(values).zip(proofs) {
            let mut temp = w * z;
            temp += c;
            let c = temp;
            g_multiplier += &(randomizer * v);
            total_c += c * randomizer;
            total_w += w * randomizer;
            randomizer = u128::rand(rng).into();
        }
        total_c -= C::G1Affine::generator() * g_multiplier;
        total_c -= powers.g1_tau() * gamma_g_multiplier;

        let affine_points = C::G1::normalize_batch(&[-total_w, total_c]);
        let (total_w, total_c) = (affine_points[0], affine_points[1]);

        C::multi_pairing(
            [total_w, total_c],
            [powers.g2_tau(), C::G2Affine::generator()],
        )
        .0
        .is_one()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bw6_761::BW6_761 as Bw6Curve;
    use ark_poly::Polynomial;
    use ark_std::test_rng;

    type Scalar = <Bw6Curve as Pairing>::ScalarField;
    type UniPoly = DensePolynomial<Scalar>;

    #[test]
    fn commitment() {
        let tau = Scalar::from(2u64);
        let poly = UniPoly::from_coefficients_slice(&[
            Scalar::from(3u64),
            -Scalar::from(2u64),
            Scalar::one(),
        ]);
        let poly_tau = poly.evaluate(&tau);
        assert_eq!(poly_tau, Scalar::from(3u64));

        let powers = Powers::<Bw6Curve>::unsafe_setup(tau, 10);
        let com_g1 = powers.commit_g1(&poly);
        let com_g2 = powers.commit_g2(&poly);

        assert_eq!(com_g1, (powers.g1[0] * poly_tau).into_affine());
        assert_eq!(com_g2, (powers.g2[0] * poly_tau).into_affine());
    }

    #[test]
    fn batch_verification() {
        let rng = &mut test_rng();
        for _ in 0..10 {
            let mut degree = 0;
            while degree <= 1 {
                degree = usize::rand(rng) % 20;
            }

            let tau = Scalar::rand(rng);
            let powers = Powers::<Bw6Curve>::unsafe_setup(tau, degree + 1);

            let mut comms = Vec::new();
            let mut values = Vec::new();
            let mut points = Vec::new();
            let mut proofs = Vec::new();

            for _ in 0..10 {
                let poly = UniPoly::rand(degree, rng);
                let comm = powers.commit_g1(&poly).into_affine();
                let point = Scalar::rand(rng);
                let value = poly.evaluate(&point);
                let proof = Kzg::proof(&poly, point, value, &powers);
                assert!(Kzg::verify_scalar(proof, comm, point, value, &powers));

                comms.push(comm);
                values.push(value);
                points.push(point);
                proofs.push(proof);
            }

            assert!(Kzg::batch_verify(
                &proofs, &comms, &points, &values, &powers, rng
            ));
        }
    }

    #[test]
    fn commitment_equality() {
        let rng = &mut test_rng();
        let degree = 16;
        let domain = GeneralEvaluationDomain::new(degree).unwrap();
        let tau = Scalar::rand(rng);
        let powers = Powers::<Bw6Curve>::unsafe_setup(tau, degree);
        let powers_eip = Powers::<Bw6Curve>::unsafe_setup_eip_4844(tau, degree);

        let coeffs = (0..degree).map(|_| Scalar::rand(rng)).collect();
        let poly = UniPoly { coeffs };

        let evals = poly.evaluate_over_domain_by_ref(domain);
        let com_p = powers.commit_g1(&poly);
        let com_p_eip = powers_eip.commit_scalars_g1(&evals.evals);

        assert_eq!(com_p, com_p_eip);
    }
}
