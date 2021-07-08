use ferveo::*;

pub fn main() {
    pvdkg::<ark_bls12_381::Bls12_381>();
}

pub fn pvdkg<E: ark_ec::PairingEngine>() {
    use ark_ec::{AffineCurve, ProjectiveCurve};
    let rng = &mut ark_std::test_rng();

    let params = Params {
        tau: 0u64,
        failure_threshold: 1,
        security_threshold: 512 / 3,
        total_weight: 512,
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
        for participant in contexts.iter_mut() {
            if dealt_weight < params.total_weight - params.security_threshold {
                let msg = participant.share(rng).unwrap();
                messages.push_back(msg);
                dealt_weight += participant.participants[participant.me].weight;
            }
        }
        msg_loop(&mut contexts, &mut messages);
        let agg = contexts[0].aggregate_without_serialize();
        let agg_signer = contexts[0].ed_key.public.clone();
        for participant in contexts.iter_mut() {
            participant
                .handle_message(&agg_signer, agg.clone())
                .unwrap();
            //assert_eq!(participant.state, DKGState::Success);
        }

        contexts[0].final_key();
    }
}
