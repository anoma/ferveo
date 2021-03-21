#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]
#![allow(unused_imports)]

use crate::poly;
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
use std::collections::{BTreeMap};
//use ed25519_dalek::{Signature, Signer, PublicKey, Verifier};
use ed25519_dalek as ed25519;
use crate::syncvss;

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
    pub recv_dealings : HashMap<[u8;32], syncvss::sh::DealtShares>,
    pub recv_shares : BTreeMap<u32, syncvss::Share>,
    pub recv_weight : u32,
}

impl Context {
    pub fn new(
        me: ParticipantKeys,
        my_signature_key: ed25519::Keypair,
        tau: u32,
        params: Params,
        weights: &[(ParticipantKeys, u32)],
    ) -> Context {
        let mut rng = rand::thread_rng();
        let my_encryption_key = crypto_box::SecretKey::generate(&mut rng);
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
            if *keys == me {
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
            recv_dealings : HashMap::new(),
            recv_shares : BTreeMap::new(),
            recv_weight : 0u32,
        }
    }
}
