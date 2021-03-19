use ark_bls12_381::{
    Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ark_ff::{Field, One, Zero};
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, UVPolynomial};
use ark_poly_commit::kzg10::{
    Commitment, Powers, Proof, Randomness, UniversalParams, VerifierKey, KZG10,
};
use ferveo::fastkzg::*;
use ferveo::fastpoly::*;

use criterion::{criterion_group, criterion_main, Criterion};

pub fn bench_kzg(c: &mut Criterion) {
    use ark_poly::Polynomial;

    let mut group = c.benchmark_group("batch commitment");
    group.sample_size(10);

    type KZG = KZG10<Bls12_381, DensePolynomial<Fr>>;
    let rng = &mut ark_std::test_rng();

    let n = 10;
    let total_weight = 1 << n;
    {
        let degree = 2 * total_weight / 3;

        let (pp, powers_of_h) = setup(degree, rng).unwrap();
        group.bench_function("setup", |b| b.iter(|| setup(degree, rng)));

        //let (ck, vk) = KZG::trim(&pp, degree);
        //12 us
        //group.bench_function("trim", |b| b.iter(|| trim(&pp, degree)));

        for _ in 0..1 {
            let p = DensePolynomial::<Fr>::rand(degree, rng);

            let comm = g1_commit(&pp.powers_of_g, &p).unwrap();
            group.bench_function("commit", |b| {
                b.iter(|| g1_commit(&pp.powers_of_g, &p))
            });

            let domain =
                ark_poly::Radix2EvaluationDomain::<Fr>::new(total_weight)
                    .unwrap();

            let mut point = Fr::one();

            let mut share_domain =
                Vec::with_capacity(1 << domain.log_size_of_group);
            let mut t = Fr::one();
            for _ in 0..1 << domain.log_size_of_group {
                share_domain.push(t);
                t *= domain.group_gen;
            }

            let share_domain = SubproductDomain::new(share_domain);

            let evals = share_domain
                .u
                .iter()
                .map(|x| p.evaluate(x))
                .collect::<Vec<Fr>>();

            let poly = share_domain.fast_interpolate(&evals);

            group.bench_function("interpolate", |b| {
                b.iter(|| {
                    let poly = share_domain.fast_interpolate(&evals);
                })
            });
            let proof =
                AmortizedOpeningProof::new(&pp.powers_of_g, &p, &domain)
                    .unwrap();

            let proof = proof.combine(
                &(0..1 << domain.log_size_of_group),
                &evals,
                &share_domain,
            );

            group.bench_function("open amortized", |b| {
                b.iter(|| {
                    let proof = AmortizedOpeningProof::new(
                        &pp.powers_of_g,
                        &p,
                        &domain,
                    )
                    .unwrap();

                    let proof = proof.combine(
                        &(0..1 << domain.log_size_of_group),
                        &evals,
                        &share_domain,
                    );
                })
            });

            let poly_commit = g1_commit(&pp.powers_of_g, &poly).unwrap();

            assert!(check_batched(
                &powers_of_h,
                &comm,
                &g2_commit(&powers_of_h, &share_domain.t.m).unwrap(),
                &poly_commit,
                &proof.into()
            )
            .unwrap());

            group.bench_function("check_batch", |b| {
                b.iter(|| {
                    assert!(check_batched(
                        &powers_of_h,
                        &comm,
                        &g2_commit(&powers_of_h, &share_domain.t.m).unwrap(),
                        &poly_commit,
                        &proof.into()
                    )
                    .unwrap());
                })
            });
        }
    }
}

criterion_group!(benches, bench_kzg);
criterion_main!(benches);
