use ark_bls12_381::Fr;
use ark_ff::UniformRand;
pub type Scalar = Fr;

use criterion::{criterion_group, criterion_main, Criterion};
use ferveo::poly;

// generating public polynomials
pub fn bench_public(c: &mut Criterion) {
    // use a fixed seed for reproducability
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);

    let mut gen_public = |threshold: u32| {
        let secret = poly::random_secret(threshold, Scalar::rand(&mut
        rng), &mut rng);
        let _public = poly::public(&secret);
    };

    let mut group = c.benchmark_group("generate public polynomials");
    group.sample_size(10);

    group.bench_function("threshold 08", |b| b.iter(|| gen_public(08)));
    group.measurement_time(core::time::Duration::new(30, 0));
    group.bench_function("threshold 32", |b| b.iter(|| gen_public(32)));
    group.measurement_time(core::time::Duration::new(60, 0));
    group.bench_function("threshold 64", |b| b.iter(|| gen_public(64)));
}

criterion_group!(benches, bench_public);
criterion_main!(benches);
