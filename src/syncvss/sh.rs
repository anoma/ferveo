#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]

use crate::poly;

use ark_bls12_381::{Fr, G1Affine};
use ark_serialize::CanonicalSerialize;
use crypto_box::aead::Aead;
use ed25519_dalek::Signer;
use either::Either;
use num::integer::div_ceil;
use num::Zero;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use ed25519_dalek as ed25519;

use ark_poly::{
    polynomial::univariate::DensePolynomial, polynomial::UVPolynomial,
    EvaluationDomain, Polynomial, Radix2EvaluationDomain,
};

use crate::dkg;
use crate::syncvss::params::Params;

type Scalar = Fr;

pub type VSSShareCiphertext = (Vec<u8>, ed25519::Signature);

pub struct Context {
    /* Map keyed by sha2-256 hashes of commitments.
    The values of the map are pairs of node indexes and scalars */
    A: HashMap<[u8; 32], HashSet<(u32, Scalar)>>,
    /* Counters for `echo` messages.
    The keys of the map are sha2-256 hashes. */
    e: HashMap<[u8; 32], u32>,
    i: u32, // index of this node in the setup
    /* Counters for `ready` messages.
    The keys of the map are sha2-256 hashes. */
    params: Params,
    r: HashMap<[u8; 32], u32>,
}

impl Context {
    pub fn init(
        params: Params,
        i: u32, // index of this node's public key in the setup
    ) -> Self {
        let A = HashMap::new();
        let e = HashMap::new();
        let r = HashMap::new();

        Context { A, e, i, params, r }
    }

    pub fn share<R: rand::Rng + Sized>(
        &self,
        rng: &mut R,
        s: Scalar,
        dkg: &dkg::Context,
    ) -> Vec<VSSShareCiphertext> {
        let mut phi = DensePolynomial::<Scalar>::rand(self.params.t as usize, rng);
        phi.coeffs[0] = s;
        let evals = phi.evaluate_over_domain_by_ref(dkg.domain);

        dkg
            .participants
            .iter()
            .enumerate()
            .map(|(i, participant)| {
                encrypt_and_sign(
                    &evals.evals[participant.share_index
                        ..participant.share_index
                            + participant.weight as usize],
                    dkg.tau,
                    dkg.my_index,
                    i as u32,
                    &participant.keys.encryption_key,
                    &dkg.my_encryption_key,
                    &dkg.my_signature_key,
                )
            })
            .collect()
    }
}

pub fn encrypt_and_sign(
    shares: &[Scalar],
    tau: u32,
    sender: u32,
    receiver: u32,
    public_key: &crypto_box::PublicKey,
    secret_key: &crypto_box::SecretKey,
    sign_secret_key: &ed25519::Keypair,
) -> VSSShareCiphertext {
    let mut msg = Vec::<u8>::with_capacity(shares.len() * 4);
    shares.serialize(&mut msg[..]);
    //for s in shares.iter() {

    //    msg.extend_with_slice(s. );
    //}

    let msg_box = crypto_box::ChaChaBox::new(&public_key, &secret_key);
    let mut rng = rand::thread_rng();
    let nonce = crypto_box::generate_nonce(&mut rng);

    let mut aad = [0u8; 12];
    aad[0..2].copy_from_slice(&tau.to_le_bytes());
    aad[2..4].copy_from_slice(&sender.to_le_bytes());
    aad[4..6].copy_from_slice(&receiver.to_le_bytes());

    let ciphertext =
        msg_box.encrypt(&nonce, crypto_box::aead::Payload { msg: &msg, aad: &aad }).unwrap();

    let signature = sign_secret_key.sign(&ciphertext);
    (ciphertext, signature)
}
