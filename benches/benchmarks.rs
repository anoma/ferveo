use ark_ff::UniformRand;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ferveo::poly;
use rand::SeedableRng;

// generating public polynomials
pub fn bench_public(c: &mut Criterion) {
    // use a fixed seed for reproducability
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);

    let mut gen_public = |threshold: u32| {
        let s = ark_bls12_381::Fr::rand(&mut rng);
        let secret = poly::random_secret(threshold, s, &mut rng);
        let _public = poly::public(&secret);
    };

    let mut rng = rand::rngs::StdRng::seed_from_u64(0);

    let mut gen_public_wnaf = |threshold: u32| {
        let s = ark_bls12_381::Fr::rand(&mut rng);
        let secret = poly::random_secret(threshold, s, &mut rng);
        let _public = poly::public_wnaf(&secret);
    };

    let mut group = c.benchmark_group("generate public polynomials");
    group.sample_size(10);

    group.bench_function(BenchmarkId::new("doubleadd", 8), |b| {
        b.iter(|| gen_public(08))
    });
    group.measurement_time(core::time::Duration::new(60, 0));
    group.bench_function(BenchmarkId::new("doubleadd", 32), |b| {
        b.iter(|| gen_public(32))
    });
    group.measurement_time(core::time::Duration::new(70, 0));
    group.bench_function(BenchmarkId::new("doubleadd", 64), |b| {
        b.iter(|| gen_public(64))
    });

    group.bench_function(BenchmarkId::new("wnaf", 8), |b| {
        b.iter(|| gen_public_wnaf(08))
    });
    group.measurement_time(core::time::Duration::new(60, 0));
    group.bench_function(BenchmarkId::new("wnaf", 32), |b| {
        b.iter(|| gen_public_wnaf(32))
    });
    group.measurement_time(core::time::Duration::new(70, 0));
    group.bench_function(BenchmarkId::new("wnaf", 64), |b| {
        b.iter(|| gen_public_wnaf(64))
    });
}

// generating secret shares
pub fn bench_shares(c: &mut Criterion) {
    // use a fixed seed for reproducability
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);

    let mut gen_shares = |threshold: u32, participants: u32| {
        let s = ark_bls12_381::Fr::rand(&mut rng);
        let secret = poly::random_secret(threshold, s, &mut rng);
        for i in 0..participants {
            let _share = poly::share(&secret, i.into());
        }
    };

    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut gen_shares_fft = |threshold: u32, participants: u32| {
        let s = ark_bls12_381::Fr::rand(&mut rng);
        let secret = poly::random_secret(threshold, s, &mut rng);
        let _shares = poly::multi_share(&secret, participants as usize);
    };

    let mut group = c.benchmark_group("generate secret shares");
    group.sample_size(10);

    group.bench_function(BenchmarkId::new("old", 8), |b| {
        b.iter(|| gen_shares(08, 16))
    });
    group.measurement_time(core::time::Duration::new(60, 0));
    group.bench_function(BenchmarkId::new("old", 32), |b| {
        b.iter(|| gen_shares(32, 64))
    });
    group.measurement_time(core::time::Duration::new(70, 0));
    group.bench_function(BenchmarkId::new("old", 64), |b| {
        b.iter(|| gen_shares(64, 128))
    });
    group.measurement_time(core::time::Duration::new(300, 0));
    group.bench_function(BenchmarkId::new("old", 128), |b| {
        b.iter(|| gen_shares(128, 256))
    });

    group.bench_function(BenchmarkId::new("old", 256), |b| {
        b.iter(|| gen_shares(256, 512))
    });
    group.measurement_time(core::time::Duration::new(60, 0));

    group.bench_function(BenchmarkId::new("fft", 8), |b| {
        b.iter(|| gen_shares_fft(08, 16))
    });
    group.measurement_time(core::time::Duration::new(60, 0));
    group.bench_function(BenchmarkId::new("fft", 32), |b| {
        b.iter(|| gen_shares_fft(32, 64))
    });
    group.measurement_time(core::time::Duration::new(70, 0));
    group.bench_function(BenchmarkId::new("fft", 64), |b| {
        b.iter(|| gen_shares_fft(64, 128))
    });
    group.measurement_time(core::time::Duration::new(300, 0));
    group.bench_function(BenchmarkId::new("fft", 128), |b| {
        b.iter(|| gen_shares_fft(128, 256))
    });
    group.bench_function(BenchmarkId::new("fft", 256), |b| {
        b.iter(|| gen_shares_fft(256, 512))
    });
    group.bench_function(BenchmarkId::new("fft", 512), |b| {
        b.iter(|| gen_shares_fft(512, 1024))
    });

    group.finish();
}

criterion_group!(benches, bench_public);
//criterion_group!(benches, bench_shares);
criterion_main!(benches);
