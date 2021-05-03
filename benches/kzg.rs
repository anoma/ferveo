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

    let n = 14;
    let total_weight = 1 << n;
    {
        let degree = 2 * total_weight / 3;

        let (pp, powers_of_h) = setup(degree, rng).unwrap();
        group.bench_function("setup", |b| b.iter(|| setup(degree, rng)));

        let (ck, vk) = trim(&pp, degree);
        //12 us
        //group.bench_function("trim", |b| b.iter(|| trim(&pp, degree)));

        for _ in 0..1 {
            let p = DensePolynomial::<Fr>::rand(degree, rng);

            let (comm, rand) = KZG::commit(&ck, &p, None, None).unwrap();
            group.bench_function("commit", |b| {
                b.iter(|| KZG::commit(&ck, &p, None, None))
            });

            let domain =
                ark_poly::Radix2EvaluationDomain::<Fr>::new(total_weight)
                    .unwrap();

            //5.5us
            /*group.bench_function("domain::new", |b| {
                b.iter(|| {
                    ark_poly::Radix2EvaluationDomain::<Fr>::new(total_weight)
                })
            });*/

            let openings = open_amortized(&ck, &p, n).unwrap();
            group.bench_function("open amortized", |b| {
                b.iter(|| open_amortized(&ck, &p, n))
            });

            group.bench_function("open amortized unnormalized", |b| {
                b.iter(|| open_amortized_unnormalized(&ck, &p, n))
            });

            let affine_openings = openings
                .iter()
                .map(|p| (*p).into())
                .collect::<Vec<G1Affine>>();

            let mut point = Fr::one();

            let mut share_domain =
                Vec::with_capacity(1 << domain.log_size_of_group);
            let mut t = Fr::one();
            for _ in 0..1 << domain.log_size_of_group {
                share_domain.push(t);
                t *= domain.group_gen;
            }

            /*group.bench_function("share domain", |b| { //23 us
                b.iter(|| {
                    let mut share_domain =
                        Vec::with_capacity(1 << domain.log_size_of_group);
                    let mut t = Fr::one();
                    for _ in 0..1 << domain.log_size_of_group {
                        share_domain.push(t);
                        t *= domain.group_gen;
                    }
                })
            });*/

            /*let A_I = compute_ai(&share_domain);
            group.bench_function("compute_ai", |b| {
                b.iter(|| compute_ai(&share_domain))
            });*/
            let A_I = subproduct_tree(&share_domain);

            let A_I_prime = derivative(&A_I.M);

            //51 us
            //group.bench_function("derivative", |b| b.iter(|| derivative(&A_I)));

            /*let c_i = compute_ci(&share_domain, &A_I_prime);
            group.bench_function("compute_ci", |b| {
                b.iter(|| compute_ci(&share_domain, &A_I_prime))
            });*/

            let evals = share_domain
                .iter()
                .map(|x| p.evaluate(x))
                .collect::<Vec<Fr>>();

            let (poly, proof) = fast_interpolate_and_batch(
                &share_domain,
                &evals,
                &openings,
                &A_I,
                None,
            );
            group.bench_function("interpolate", |b| {
                b.iter(|| {
                    fast_interpolate_and_batch(
                        &share_domain,
                        &evals,
                        &openings,
                        &A_I,
                        None,
                    )
                })
            });

            /*            group.bench_function("batch_proofs", |b| {
                b.iter(|| batch_proofs(&c_i, &openings))
            });
            let poly = lagrange_interpolate(
                &share_domain,
                &share_domain
                    .iter()
                    .map(|x| p.evaluate(x))
                    .collect::<Vec<Fr>>(),
                &A_I,
                &A_I_prime,
            );
            group.bench_function("interpolate", |b| {
                b.iter(|| {
                    lagrange_interpolate(
                        &share_domain,
                        &share_domain
                            .iter()
                            .map(|x| p.evaluate(x))
                            .collect::<Vec<Fr>>(),
                        &A_I,
                        &A_I_prime,
                    )
                })
            });*/

            assert!(check_batched(
                &powers_of_h,
                &ck,
                &vk,
                &comm,
                &A_I.M,
                &poly,
                &proof.into(),
            )
            .unwrap());
            group.bench_function("check_batch", |b| {
                b.iter(|| {
                    check_batched(
                        &powers_of_h,
                        &ck,
                        &vk,
                        &comm,
                        &A_I.M,
                        &poly,
                        &proof.into(),
                    )
                })
            });
        }
    }
}

criterion_group!(benches, bench_kzg);
criterion_main!(benches);
