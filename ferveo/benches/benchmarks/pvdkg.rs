use criterion::{criterion_group, criterion_main, Criterion};
use ferveo::*;

pub fn dkgs(c: &mut Criterion) {
    // use a fixed seed for reproducability
    use rand::SeedableRng;
    let _rng = rand::rngs::StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("compare DKGs with 8192 shares");
    group.sample_size(10);

    //Benchmarking compare DKGs with 8192 shares/Pedersen Pallas: Collecting 10 sample                                                                                compare DKGs with 8192 shares/Pedersen Pallas
    //time:   [95.895 s 97.154 s 98.507 s]
    /*group.bench_function("Pedersen Pallas", |b| {
        b.iter(|| pedersen::<ark_pallas::Affine>())
    });
    group.measurement_time(core::time::Duration::new(30, 0));*/
    // Benchmarking compare DKGs with 8192 shares/Pedersen BLS12-381: Collecting 10 sam                                                                                compare DKGs with 8192 shares/Pedersen BLS12-381
    //time:   [177.12 s 178.73 s 180.47 s]
    /*group.bench_function("Pedersen BLS12-381", |b| {
        b.iter(|| pedersen::<ark_bls12_381::G1Affine>())
    });*/
    // 2130.7 seconds per iteration to verify pairwise
    group.measurement_time(core::time::Duration::new(60, 0));
    group.bench_function("PVDKG BLS12-381", |b| {
        b.iter(pvdkg::<ark_bls12_381::Bls12_381>)
    });
}

use pprof::criterion::{Output, PProfProfiler};

criterion_group! {
    name = pvdkg_bls;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = dkgs
}

criterion_main!(pvdkg_bls);

fn create_info(vp: u64) -> TendermintValidator {
    TendermintValidator { power: vp }
}

pub fn pvdkg<E: ark_ec::PairingEngine>() {
    use ark_ec::{AffineCurve, ProjectiveCurve};
    let rng = &mut ark_std::test_rng();
    //use rand_old::SeedableRng;
    //let ed_rng = &mut rand_old::rngs::StdRng::from_seed([0u8; 32]);

    let params = Params {
        tau: 0u64,
        security_threshold: 300 / 3,
        total_weight: 300,
    };
    let validator_set = ValidatorSet {
        validators: (1..11u64)
            .map(|vp| TendermintValidator { power: vp })
            .collect::<Vec<_>>(),
    };

    let validator_keys = (0..10)
        .map(|_| {
            ferveo_common::PublicKey::<ark_bls12_381::Bls12_381>::default()
        })
        .collect::<Vec<_>>();

    // for _ in 0..1 {
    let mut contexts = vec![];
    for me in 0..10 {
        contexts.push(
            PubliclyVerifiableDkg::<ark_bls12_381::Bls12_381>::new(
                validator_set.clone(),
                &validator_keys,
                params.clone(),
                me,
                rng,
            )
            .unwrap(),
        );
    }
    use std::collections::VecDeque;
    let mut messages = VecDeque::new();

    let mut dealt_weight = 0u32;
    for participant in contexts.iter_mut() {
        if dealt_weight < params.total_weight - params.security_threshold {
            let msg = participant.share(rng).unwrap();
            let msg: Message<ark_bls12_381::Bls12_381> = msg; //.verify().unwrap().1;
            messages.push_back((participant.me, msg));
            dealt_weight += participant.validators[participant.me].weight;
        }
    }
    for msg in messages.iter() {
        for node in contexts.iter_mut() {
            node.handle_message(msg.0 as u32, msg.1.clone()).unwrap();
        }
    }

    let tpke_pubkey = contexts[0].final_key();
}
