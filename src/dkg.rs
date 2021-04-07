#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]
#![allow(unused_imports)]

//use crate::poly;
use ark_bls12_381::{Fr, G1Affine};
use num::integer::div_ceil;
use rand::Rng;
use std::collections::{BTreeSet, HashMap};
use std::rc::Rc;
type Scalar = Fr;
use ark_poly::{
    polynomial::univariate::DensePolynomial, polynomial::UVPolynomial,
    EvaluationDomain, Polynomial,
};
use std::collections::BTreeMap;
//use ed25519_dalek::{Signature, Signer, PublicKey, Verifier};
use crate::syncvss;
use ed25519_dalek as ed25519;

// DKG parameters
#[derive(Copy, Clone)]
pub struct Params {
    pub f: u32, // failure threshold
    //pub n: u32, // number of participants
    pub t: u32, // threshold
}

#[derive(Copy, Clone, PartialEq)]
pub struct ParticipantKeys {
    pub signing_key: ed25519::PublicKey,
    pub encryption_key: crypto_box::PublicKey,
}
pub struct Participant {
    pub keys: ParticipantKeys,
    pub weight: u32,
    pub share_index: usize,
    pub share_domain: Option<Vec<Scalar>>, // Not every share domain needs to be generated, necessarily
}

pub struct Context {
    pub tau: u32,
    pub my_index: u32,
    pub my_encryption_key: crypto_box::SecretKey,
    pub my_signature_key: ed25519::Keypair,
    pub params: Params,
    pub participants: Vec<Participant>,
    pub domain: ark_poly::Radix2EvaluationDomain<Scalar>,
    pub recv_dealings: HashMap<[u8; 32], syncvss::sh::DealtShares>,
    pub recv_shares: BTreeMap<u32, syncvss::Share>,
    pub recv_weight: u32,
}

impl Context {
    pub fn new(
        me: &ParticipantKeys,
        my_encryption_key: crypto_box::SecretKey,
        my_signature_key: ed25519::Keypair,
        tau: u32,
        params: Params,
        weights: &[(ParticipantKeys, u32)],
    ) -> Context {
        let mut rng = rand::thread_rng();
        //let my_encryption_key = crypto_box::SecretKey::generate(&mut rng);
        let total_weight: u32 = weights.iter().map(|(_, i)| *i).sum();
        let domain = ark_poly::Radix2EvaluationDomain::<Scalar>::new(
            total_weight as usize,
        )
        .unwrap();

        let mut participants = vec![];
        let mut share_element = Scalar::from(1u64);
        let mut share_index = 0usize;
        let mut my_index = None;
        for (i, (keys, weight)) in weights.iter().enumerate() {
            if *keys == *me {
                my_index = Some(i as u32);
            }
            let mut share_domain = vec![];
            for _share in 0..*weight as usize {
                share_domain.push(share_element);
                share_element *= domain.group_gen;
            }
            let share_domain = Some(share_domain);
            participants.push(Participant {
                keys: *keys,
                weight: *weight,
                share_index,
                share_domain,
            });
            share_index += *weight as usize;
        }
        let my_index = my_index.unwrap();

        Context {
            tau,
            my_index,
            my_encryption_key,
            my_signature_key,
            params,
            participants,
            domain,
            recv_dealings: HashMap::new(),
            recv_shares: BTreeMap::new(),
            recv_weight: 0u32,
        }
    }
}

#[test]
fn dkg() {
    let mut rng = rand::thread_rng();

    for _ in 0..10 {
        let mut secret_participants_x = vec![];
        for _ in 0..7 {
            secret_participants_x
                .push(crypto_box::SecretKey::generate(&mut rng));
        }

        let mut participants_ed = vec![];
        for _ in 0..7 {
            participants_ed.push(ed25519::Keypair::generate(&mut rng));
        }

        let sender = ed25519::Keypair::generate(&mut rng);
        let receiver = ed25519::Keypair::generate(&mut rng);

        let sender_x = crypto_box::SecretKey::generate(&mut rng);
        let receiver_x = crypto_box::SecretKey::generate(&mut rng);

        let mut participant_keys = vec![
            ParticipantKeys {
                signing_key: sender.public,
                encryption_key: crypto_box::PublicKey::from(&sender_x.clone()),
            },
            ParticipantKeys {
                signing_key: receiver.public,
                encryption_key: crypto_box::PublicKey::from(
                    &receiver_x.clone(),
                ),
            },
        ];

        for i in 2..9 {
            participant_keys.push(ParticipantKeys {
                signing_key: participants_ed[i - 2].public,
                encryption_key: crypto_box::PublicKey::from(
                    &secret_participants_x[i - 2].clone(),
                ),
            });
        }
        let mut weights = vec![];
        for pk in &participant_keys {
            weights.push((*pk, 5))
        }

        let mut send_context = Context::new(
            &participant_keys[0],
            sender_x,
            sender,
            0u32,
            Params { f: 1, t: 3 * 5 },
            weights.as_slice(),
        );

        use ark_ff::Zero;
        let msg =
            syncvss::sh::deal_shares(&mut rng, Scalar::zero(), &send_context);

        let mut recv_context = Context::new(
            &participant_keys[1],
            receiver_x,
            receiver,
            0u32,
            Params { f: 1, t: 3 * 5 },
            weights.as_slice(),
        );

        let shares = syncvss::sh::recv_dealing(&mut recv_context, msg).unwrap();
    }
}
