#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]
#![allow(unused_imports)]

//use ark_poly_commit::kzg10::{Powers, VerifierKey};

use crate::*;
use anyhow::anyhow;
use ark_ec::AffineCurve;
use ark_ec::ProjectiveCurve;
use ark_ff::Zero;
use ark_ff::{Field, One};
use ark_poly::{
    polynomial::univariate::DensePolynomial, polynomial::UVPolynomial,
    EvaluationDomain, Polynomial,
};
use ed25519_dalek as ed25519;
use serde::*;

pub mod context;
pub mod participant;
pub mod pedersen;
pub use context::*;
pub use participant::*;
pub use pedersen::*;

// DKG parameters
#[derive(Copy, Clone, Debug)]
pub struct Params {
    pub failure_threshold: u32,  // failure threshold
    pub security_threshold: u32, // threshold
    pub total_weight: u32,       // total weight
}

#[derive(Clone)]
pub enum DKGState<E>
where
    E: Engine,
{
    Init {
        participants: Vec<ParticipantBuilder<E>>,
    },
    Sharing {
        finalized_weight: u32,
    },
    Success,
    Failure,
}

#[derive(Clone, Debug)]
pub struct DistributedKeyShares<Scalar: PrimeField> {
    pub local_shares: Vec<Scalar>,
}

pub trait Engine: Sized {
    // TODO: can these associated types be cleaned up?
    type VSS: VSS<Self>;
    type SessionKey: Serialize + de::DeserializeOwned + Clone;
    type SessionKeypair: Clone;
    type PublicKey: AffineCurve;
    type Scalar: PrimeField + FftField;
    type DealingMsg: Serialize + de::DeserializeOwned + Clone;
    type ReadyMsg: Serialize + de::DeserializeOwned + Clone;
    type FinalizeMsg: Serialize + de::DeserializeOwned + Clone;

    fn new_session_keypair<R: Rng>(rng: &mut R) -> Self::SessionKeypair;
    fn session_key_public(
        session_keypair: &Self::SessionKeypair,
    ) -> Self::SessionKey;
    fn handle_other(
        dkg: &mut Context<Self>,
        signer: &ed25519::PublicKey,
        payload: &MessagePayload<Self>,
    ) -> Result<Option<SignedMessage>>;
}

#[test]
fn dkg() {
    let rng = &mut ark_std::test_rng();
    type Affine = ark_pallas::Affine;
    use vss::dh;

    let params = Params {
        failure_threshold: 1,
        security_threshold: 330,
        total_weight: 1000,
    };

    for _ in 0..1 {
        let mut contexts = vec![];
        for _ in 0..10 {
            contexts.push(
                Context::new(
                    0u32, //tau
                    ed25519::Keypair::generate(rng),
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
            |contexts: &mut Vec<Context<PedersenDKG<Affine>>>,
             messages: &mut VecDeque<SignedMessage>| loop {
                if messages.is_empty() {
                    break;
                }
                let message = messages.pop_front().unwrap();
                for node in contexts.iter_mut() {
                    let new_msg = node.handle_message(&message).unwrap();
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

        for participant in contexts.iter_mut() {
            let msg = participant.deal_if_turn(rng).unwrap();
            if let Some(msg) = msg {
                messages.push_back(msg);
            }
        }

        use ark_ff::Zero;
        let mut final_secret = Affine::zero();
        for c in contexts.iter() {
            for v in c.vss.values() {
                if let Some(finalize_msg) = v.finalize_msg {
                    final_secret = final_secret + finalize_msg.rebased_secret;
                }
            }
        }
        let final_secret: Affine = final_secret.into();

        msg_loop(&mut contexts, &mut messages);

        for participant in contexts.iter() {
            assert!(matches!(participant.state, DKGState::Success));
        }
        let final_keys =
            contexts.iter().map(|c| c.final_key()).collect::<Vec<_>>();

        assert!(final_keys.iter().all(|&key| key == final_secret));
    }
}
