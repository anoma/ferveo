use ferveo::*;

pub fn main() {
    pvdkg::<ark_bls12_381::Bls12_381>();
}

pub fn pvdkg<E: ark_ec::PairingEngine>() {
    use ark_ec::{AffineCurve, ProjectiveCurve};
    let rng = &mut ark_std::test_rng();
    use rand_old::SeedableRng;
    let ed_rng = &mut rand_old::rngs::StdRng::from_seed([0u8; 32]);

    let params = Params {
        tau: 0u64,
        security_threshold: 512 / 3,
        total_weight: 512,
    };

    for _ in 0..1 {
        let mut contexts = vec![];
        for _ in 0..10 {
            contexts.push(
                PubliclyVerifiableDKG::<E>::new(
                    ed25519_dalek::Keypair::generate(ed_rng),
                    params.clone(),
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
                pvss.push((participant.ed_key.public.clone(), msg));
                dealt_weight += participant.participants[participant.me].weight;
            }
        }
        for msg in pvss.iter() {
            for node in contexts.iter_mut() {
                node.handle_message(&msg.0, msg.1.clone()).unwrap();
            }
        }
        msg_loop(&mut contexts, &mut messages);
        let agg = contexts[0].aggregate();
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
