use criterion::{black_box, criterion_group, criterion_main, Criterion};
use subproductdomain::*;

use ark_ec::PairingEngine;
use ark_ff::{One, Zero};
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly::UVPolynomial;
use ark_std::UniformRand;

type Fr = <ark_bls12_381::Bls12_381 as PairingEngine>::Fr;

pub fn bench_subproductdomain(c: &mut Criterion) {
    let mut group = c.benchmark_group("Subproduct domain benchmarks");
    group.sample_size(10);
    group.measurement_time(core::time::Duration::new(2, 0));

    let rng = &mut ark_std::test_rng();

    for d in [10, 100, 1000, 10000] {
        let mut points = vec![];
        let mut evals = vec![];
        for _ in 0..d {
            points.push(Fr::rand(rng));
            evals.push(Fr::rand(rng));
        }
        let s = SubproductDomain::<Fr>::new(points.clone());
        group.bench_function(
            format!("New SubproductDomain d = {}", d),
            move |b| {
                b.iter_batched(
                    || points.clone(),
                    |data| black_box(SubproductDomain::<Fr>::new(data)),
                    criterion::BatchSize::SmallInput,
                )
            },
        );

        group.bench_function(format!("interpolate d = {}", d), |b| {
            b.iter(|| black_box(s.interpolate(&evals)))
        });

        group.bench_function(format!("linear combine d = {}", d), |b| {
            b.iter(|| black_box(s.linear_combine(&evals)))
        });
        let f = s.interpolate(&evals);

        group.bench_function(format!("evaluate d = {}", d), |b| {
            b.iter(|| black_box(s.evaluate(&f)))
        });

        group.bench_function(format!("inverse lagrange d = {}", d), |b| {
            b.iter(|| black_box(s.inverse_lagrange_coefficients()))
        });

        let f = DensePolynomial::<Fr>::rand(d, rng);
        let mut g = DensePolynomial::<Fr>::rand(d / 2, rng);
        *g.last_mut().unwrap() = Fr::one(); //monic

        group.bench_function(format!("Fast divide monic d = {}", d), |b| {
            b.iter(|| black_box(fast_divide_monic::<Fr>(&f, &g)))
        });

        let p = DensePolynomial::<Fr>::rand(d, rng);
        let l = d + 4;

        group.bench_function(
            format!("inverse_mod_xl d = {} l = {}", d, l),
            |b| b.iter(|| black_box(inverse_mod_xl::<Fr>(&p, l).unwrap())),
        );
    }
}

criterion_group!(benches, bench_subproductdomain);
criterion_main!(benches);
