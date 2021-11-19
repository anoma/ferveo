use ferveo::*;
use ferveo_common::Validator;

pub fn main() {
    pvdkg::<ark_bls12_381::Bls12_381>();
}

fn create_info(vp: u64) -> tendermint::validator::Info {
    use std::convert::TryFrom;
    tendermint::validator::Info::new(
        tendermint::public_key::PublicKey::from_raw_ed25519(&vec![
            48, 163, 55, 132, 231, 147, 230, 163, 56, 158, 127, 218, 179, 139,
            212, 103, 218, 89, 122, 126, 229, 88, 84, 48, 32, 0, 185, 174, 63,
            72, 203, 52,
        ])
        .unwrap(),
        tendermint::vote::Power::try_from(vp).unwrap(),
    )
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
