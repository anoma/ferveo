use criterion::{black_box, criterion_group, criterion_main, Criterion};
use subproductdomain::*;

use super::*;
use ark_ec::PairingEngine;
use ark_ff::{One, Zero};
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly::Polynomial;
use ark_poly::UVPolynomial;
use ark_std::UniformRand;

type Fr = <ark_bls12_381::Bls12_381 as PairingEngine>::Fr;
#[test]
fn test_inverse() {
    let rng = &mut ark_std::test_rng();

    for l in [1, 2, 3, 5, 19, 25, 101].iter() {
        for degree in 0..(l + 4) {
            for _ in 0..10 {
                let p = DensePolynomial::<Fr>::rand(degree, rng);
                let p_inv = inverse_mod_xl::<Fr>(&p, *l).unwrap();
                let mut t = &p * &p_inv; // p * p^-1
                t.coeffs.resize(*l, Fr::zero()); // mod x^l
                assert_eq!(t.coeffs[0], Fr::one()); // constant term == 1
                for i in t.iter().skip(1) {
                    assert_eq!(*i, Fr::zero()); // all other terms == 0
                }
            }
        }
    }
}

#[test]
fn test_divide() {
    let rng = &mut ark_std::test_rng();

    let degree = 100;
    for g_deg in 1..100 {
        let f = DensePolynomial::<Fr>::rand(degree, rng);
        let mut g = DensePolynomial::<Fr>::rand(g_deg, rng);
        *g.last_mut().unwrap() = Fr::one(); //monic

        let (q, r) = fast_divide_monic::<Fr>(&f, &g);

        let t = &(&q * &g) + &r;

        for (i, j) in t.coeffs.iter().zip(f.coeffs.iter()) {
            assert_eq!(*i, *j);
        }
    }
}

#[test]
fn test_interpolate() {
    let rng = &mut ark_std::test_rng();
    for d in 1..100 {
        let mut points = vec![];
        let mut evals = vec![];
        for _ in 0..d {
            points.push(Fr::rand(rng));
            evals.push(Fr::rand(rng));
        }

        let s = SubproductDomain::<Fr>::new(points);
        let p = s.interpolate(&evals);

        for (x, y) in s.u.iter().zip(evals.iter()) {
            assert_eq!(p.evaluate(x), *y)
        }
    }
}

#[test]
fn test_linear_combine() {
    let rng = &mut ark_std::test_rng();
    for d in 1..100 {
        let mut u = vec![];
        let mut c = vec![];
        for _ in 0..d {
            u.push(Fr::rand(rng));
            c.push(Fr::rand(rng));
        }
        let s = SubproductDomain::<Fr>::new(u);
        let f = s.linear_combine(&c);

        let r = Fr::rand(rng);
        let m = s.t.m.evaluate(&r);
        let mut total = Fr::zero();
        for (u_i, c_i) in s.u.iter().zip(c.iter()) {
            total += m * *c_i / (r - u_i);
        }
        assert_eq!(f.evaluate(&r), total);
    }
}

#[test]
fn test_inv_lagrange() {
    for d in 1..100 {
        let mut u = vec![];
        for _ in 0..d {
            u.push(Fr::rand(rng));
        }
        let s = SubproductDomain::<Fr>::new(u);
        let f = s.inverse_lagrange_coefficients();

        for (i, j) in s.u.iter().zip(f.iter()) {
            assert_eq!(s.prime.evaluate(i), *j);
        }
    }
}

pub fn bench_subproductdomain(c: &mut Criterion) {
    let mut group = c.benchmark_group("Subproduct domain benchmarks");
    group.sample_size(10);
    group.measurement_time(core::time::Duration::new(60, 0));

    let rng = &mut ark_std::test_rng();

    for d in [10, 100, 1000, 10000] {
        let mut points = vec![];
        let mut evals = vec![];
        for _ in 0..d {
            points.push(Fr::rand(rng));
            evals.push(Fr::rand(rng));
        }
        let s = SubproductDomain::<Fr>::new(u);
        group.bench_function(format!("New SubproductDomain d = {}", d), |b| {
            b.iter(|| black_box(SubproductDomain::<Fr>::new(points)))
        });

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
