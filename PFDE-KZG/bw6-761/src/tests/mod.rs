use ark_bw6_761::BW6_761 as TestCurve;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{
    DenseUVPolynomial, EvaluationDomain, Evaluations, GeneralEvaluationDomain, Polynomial,
};
use ark_std::test_rng;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::commit::kzg::Kzg;
use crate::commit::powers_cache::PowersCache;
use crate::veck::{
    compute_beta, interpolate_indices, random_subset_indices, subset_quotient_with_vanishing_poly,
    to_vanishing_poly, verify_subset_relation_with_vanishing_poly,
};

type Scalar = <TestCurve as ark_ec::pairing::Pairing>::ScalarField;
type UniPoly = DensePolynomial<Scalar>;

fn setup_cache_dir() -> PathBuf {
    std::env::var("PFDE_KZG_SETUP_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join(".cache")
                .join("kzg")
                .join("bw6_761")
        })
}

fn setup_cache_chunk_size() -> usize {
    std::env::var("PFDE_KZG_SETUP_CHUNK_SIZE")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1 << 16)
}

fn open_powers_cache() -> PowersCache<TestCurve> {
    let root = setup_cache_dir();
    if root.join("manifest.txt").exists() {
        PowersCache::<TestCurve>::open(&root).expect("open cached powers")
    } else {
        let tau = Scalar::rand(&mut test_rng());
        PowersCache::<TestCurve>::open_or_create(&root, tau, setup_cache_chunk_size())
            .expect("create cached powers")
    }
}

fn bench_results_path() -> PathBuf {
    std::env::var("PFDE_KZG_BENCH_OUTPUT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join(".cache")
                .join("bench")
                .join("test_bench_proof_logic.csv")
        })
}

fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn write_bench_header(writer: &mut impl Write) {
    writeln!(
        writer,
        "data_size,domain_size,subset_size,lambda,beta,coded_size,proving_ms,verifying_ms"
    )
    .expect("write benchmark header");
}

fn write_bench_row(
    writer: &mut impl Write,
    data_size: usize,
    domain_size: usize,
    subset_size: usize,
    lambda: usize,
    beta: f64,
    coded_size: usize,
    proving_time: Duration,
    verifying_time: Duration,
) {
    writeln!(
        writer,
        "{data_size},{domain_size},{subset_size},{lambda},{beta:.6},{coded_size},{:.3},{:.3}",
        duration_ms(proving_time),
        duration_ms(verifying_time),
    )
    .expect("write benchmark row");
}

#[test]
fn test_bench_proof_logic() {
    let rng = &mut test_rng();
    let lambda = 128usize;
    let subset_sizes = [256usize, 512, 1024];
    let min_powers_range = subset_sizes.iter().copied().max().unwrap() + 2;
    let results_path = bench_results_path();

    if let Some(parent) = results_path.parent() {
        fs::create_dir_all(parent).expect("create benchmark output directory");
    }

    println!("Writing benchmark results to {}", results_path.display());
    let mut writer = BufWriter::new(File::create(&results_path).expect("create benchmark file"));
    write_bench_header(&mut writer);

    let mut cache = open_powers_cache();

    for exp in 10u32..=22 {
        let data_size = 1usize << exp;
        let domain_size = data_size.next_power_of_two();
        let powers_range = domain_size.max(min_powers_range);

        println!();
        println!(
            "Preparing benchmark for data_size={data_size}, domain_size={domain_size}, powers_range={powers_range}"
        );

        let setup_started = Instant::now();
        cache
            .ensure_range(powers_range)
            .expect("extend cached powers");
        let powers = cache
            .load_prefix(powers_range)
            .expect("load cached powers prefix");
        println!("KZG setup/cache load took: {:.2?}", setup_started.elapsed());

        let domain = GeneralEvaluationDomain::new(domain_size).expect("valid domain");
        let data: Vec<Scalar> = (0..domain_size).map(|_| Scalar::rand(rng)).collect();
        let evaluations = Evaluations::from_vec_and_domain(data, domain.clone());

        let interpolation_started = Instant::now();
        println!("Interpolating full polynomial...");
        let full_poly: UniPoly = evaluations.interpolate_by_ref();
        let full_commitment = powers.commit_g1(&full_poly).into_affine();
        println!(
            "Full polynomial interpolation+commit took: {:.2?}",
            interpolation_started.elapsed()
        );

        for &subset_size in &subset_sizes {
            let beta = compute_beta(subset_size, lambda);
            let coded_size = (data_size as f64 * beta).ceil() as usize;
            println!(
                "Parameters: data_size={data_size}, domain_size={domain_size}, subset_size={subset_size}, beta={beta:.6}, coded_size={coded_size}"
            );

            let proving_started = Instant::now();
            println!("Deriving random subset...");
            let subset_indices = random_subset_indices(domain_size, subset_size, rng);
            let vanishing_poly =
                DensePolynomial::from(to_vanishing_poly(subset_indices.clone(), domain.clone()));
            let t1 = Scalar::rand(rng);
            let t2 = Scalar::rand(rng);
            let masking_poly = DensePolynomial::from_coefficients_vec(vec![t1, t2]);
            let subset_poly = interpolate_indices(&evaluations, &subset_indices)
                + &masking_poly * &vanishing_poly;
            let subset_commitment = powers.commit_g1(&subset_poly).into_affine();

            println!("Creating KZG proof (pi_S_R, O_alpha, pi_alpha) logic...");
            let quotient =
                subset_quotient_with_vanishing_poly(&full_poly, &subset_poly, &vanishing_poly)
                    .unwrap();
            let quotient_commitment = powers.commit_g1(&quotient);
            let challenge = Scalar::rand(rng);
            let challenge_eval = subset_poly.evaluate(&challenge);
            let opening_proof = Kzg::<TestCurve>::proof(
                &subset_poly,
                challenge.clone(),
                challenge_eval.clone(),
                &powers,
            );
            let proving_time = proving_started.elapsed();
            println!("Proving took: {:.2?}", proving_time);

            let verifying_started = Instant::now();
            println!("Verifying KZG proof logic...");
            assert!(verify_subset_relation_with_vanishing_poly::<TestCurve>(
                full_commitment.into_group(),
                subset_commitment.clone().into_group(),
                quotient_commitment,
                &vanishing_poly,
                &powers,
            ));
            assert!(Kzg::<TestCurve>::verify_scalar(
                opening_proof,
                subset_commitment,
                challenge,
                challenge_eval,
                &powers,
            ));
            let verifying_time = verifying_started.elapsed();
            println!("Verification took: {:.2?}", verifying_time);

            write_bench_row(
                &mut writer,
                data_size,
                domain_size,
                subset_size,
                lambda,
                beta,
                coded_size,
                proving_time,
                verifying_time,
            );
            writer.flush().expect("flush benchmark row");
        }
    }

    println!("Saved benchmark results to {}", results_path.display());
}
