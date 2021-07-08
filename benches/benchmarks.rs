use criterion::{criterion_group, criterion_main, Criterion};
use ferveo::*;

pub fn dkgs(c: &mut Criterion) {
    // use a fixed seed for reproducability
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);

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
        b.iter(|| pvdkg::<ark_bls12_381::Bls12_381>())
    });
}

criterion_group!(benches, dkgs);
criterion_main!(benches);

pub fn pedersen<Affine: ark_ec::AffineCurve>() {
    let rng = &mut ark_std::test_rng();

    let params = Params {
        tau: 0u64,
        failure_threshold: 1,
        security_threshold: 8192 / 3,
        total_weight: 8192,
    };

    for _ in 0..1 {
        let mut contexts = vec![];
        for _ in 0..10 {
            contexts.push(
                PedersenDKG::<Affine>::new(
                    ed25519_dalek::Keypair::generate(rng),
                    &params,
                    rng,
                )
                .unwrap(),
            );
        }
        use std::collections::VecDeque;
        let mut messages = VecDeque::new();

        let stake = vec![
            10u64, 20u64, 30u64, 40u64, 50u64, 60u64, 70u64, 80u64, 90u64,
            100u64,
        ];
        for (participant, stake) in contexts.iter_mut().zip(stake.iter()) {
            let announce = participant.announce(*stake);
            messages.push_back(announce);
        }

        let msg_loop =
            |contexts: &mut Vec<PedersenDKG<Affine>>,
             messages: &mut VecDeque<SignedMessage>| loop {
                if messages.is_empty() {
                    break;
                }
                let signed_message = messages.pop_front().unwrap();
                for node in contexts.iter_mut() {
                    let (_, message) = signed_message.verify().unwrap();
                    let new_msg = node
                        .handle_message(&signed_message.signer, &message)
                        .unwrap();
                    if let Some(new_msg) = new_msg {
                        messages.push_back(new_msg);
                    }
                }
            };

        msg_loop(&mut contexts, &mut messages);

        for participant in contexts.iter_mut() {
            participant.finish_announce().unwrap();
        }

        msg_loop(&mut contexts, &mut messages);

        let mut dealt_weight = 0u32;
        for participant in contexts.iter_mut() {
            if dealt_weight < params.total_weight - params.security_threshold {
                let msg = participant.share(rng).unwrap();
                messages.push_back(msg);
                dealt_weight += participant.participants[participant.me].weight;
            }
        }
        msg_loop(&mut contexts, &mut messages);

        contexts[0].final_key();
    }
}

pub fn pvdkg<E: ark_ec::PairingEngine>() {
    use ark_ec::{AffineCurve, ProjectiveCurve};
    let rng = &mut ark_std::test_rng();

    let params = Params {
        tau: 0u64,
        failure_threshold: 1,
        security_threshold: 300 / 3,
        total_weight: 300,
    };

    let pvss_params = PubliclyVerifiableParams::<E> {
        g_1: E::G1Projective::prime_subgroup_generator(),
        u_hat_1: E::G2Affine::prime_subgroup_generator(),
    };

    for _ in 0..1 {
        let mut contexts = vec![];
        for _ in 0..10 {
            contexts.push(
                PubliclyVerifiableDKG::<E>::new(
                    ed25519_dalek::Keypair::generate(rng),
                    params.clone(),
                    pvss_params.clone(),
                    rng,
                )
                .unwrap(),
            );
        }
        use std::collections::VecDeque;
        let mut messages = VecDeque::new();

        let stake = (0..150u64).map(|i| i).collect::<Vec<_>>();

        for (participant, stake) in contexts.iter_mut().zip(stake.iter()) {
            let announce = participant.announce(*stake);
            messages.push_back(announce);
        }

        let msg_loop =
            |contexts: &mut Vec<PubliclyVerifiableDKG<E>>,
             messages: &mut VecDeque<SignedMessage>| loop {
                if messages.is_empty() {
                    break;
                }
                let signed_message = messages.pop_front().unwrap();
                for node in contexts.iter_mut() {
                    let (_, message) = signed_message.verify().unwrap();
                    let new_msg = node
                        .handle_message(&signed_message.signer, message)
                        .unwrap();
                    if let Some(new_msg) = new_msg {
                        messages.push_back(new_msg);
                    }
                }
            };

        msg_loop(&mut contexts, &mut messages);

        for participant in contexts.iter_mut() {
            participant.finish_announce().unwrap();
        }

        msg_loop(&mut contexts, &mut messages);

        let mut dealt_weight = 0u32;
        let mut pvss = vec![];
        for participant in contexts.iter_mut() {
            if dealt_weight < params.total_weight - params.security_threshold {
                let msg = participant.share(rng).unwrap();
                let msg: PubliclyVerifiableMessage<E> = msg.verify().unwrap().1;
                pvss.push((participant.ed_key.public.clone(), msg));
                //messages.push_back(msg);
                dealt_weight += participant.participants[participant.me].weight;
            }
        }
        for msg in pvss.iter() {
            for node in contexts.iter_mut() {
                node.handle_message(&msg.0, msg.1.clone()).unwrap();
            }
        }
        msg_loop(&mut contexts, &mut messages);

        contexts[0].final_key();
    }
}
