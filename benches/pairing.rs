use ark_bls12_381::*;
use ark_ec::*;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use redjubjub::*;
use std::convert::TryFrom;

use ark_bls12_381::*;
use rand::thread_rng;

pub fn pairing(c: &mut Criterion) {
    let rng = &mut ark_std::test_rng();
    let mut group = c.benchmark_group("pairing running time");
    group.sample_size(10);

    use ark_std::UniformRand;
    type G1Prepared = <Bls12_381 as PairingEngine>::G1Prepared;
    type G2Prepared = <Bls12_381 as PairingEngine>::G2Prepared;

    let P = (0..100)
        .map(|i| {
            G1Affine::prime_subgroup_generator()
                .mul(Fr::rand(rng))
                .into_affine()
        })
        .collect::<Vec<G1Affine>>();
    let Q = (0..100)
        .map(|i| {
            G2Affine::prime_subgroup_generator()
                .mul(Fr::rand(rng))
                .into_affine()
        })
        .collect::<Vec<G2Affine>>();
    group.measurement_time(core::time::Duration::new(20, 0));
    group.bench_function("BLS12-381 pairing", |b| {
        b.iter(|| black_box(Bls12_381::pairing(P[0], Q[0])))
    });
    let PQ = &P
        .iter()
        .zip(Q.iter())
        .map(|(i, j)| (G1Prepared::from(*i), G2Prepared::from(*j)))
        .collect::<Vec<(G1Prepared, G2Prepared)>>();

    group.bench_function("BLS12-381 G1Prepared", |b| {
        b.iter(|| {
            black_box(
                P.iter().map(|i| G1Prepared::from(*i)).collect::<Vec<_>>(),
            )
        })
    });
    group.bench_function("BLS12-381 G2Prepared", |b| {
        b.iter(|| {
            black_box(
                Q.iter().map(|i| G2Prepared::from(*i)).collect::<Vec<_>>(),
            )
        })
    });
    group.bench_function("BLS12-381 product_of_pairing G2 prepared", |b| {
        b.iter(|| {
            (
                black_box(
                    P.iter().map(|i| G1Prepared::from(*i)).collect::<Vec<_>>(),
                ),
                black_box(Bls12_381::product_of_pairings(PQ.iter())),
            )
        })
    });
    group.bench_function("BLS12-381 product_of_pairing both prepared", |b| {
        b.iter(|| black_box(Bls12_381::product_of_pairings(PQ.iter())))
    });
}

criterion_group!(benches, pairing);
criterion_main!(benches);
