#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]
#![allow(unused_imports)]

use crate::poly;

use ark_bls12_381::{Fr, G1Affine};
use ark_ec::AffineCurve;
use ark_serialize::CanonicalSerialize;
use ark_serialize::*;
use crypto_box::aead::Aead;
use ed25519_dalek::Signature;
use ed25519_dalek::Signer;
use either::Either;
use num::integer::div_ceil;
use num::Zero;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
//use serde::{Serialize, Deserialize};
use ed25519_dalek as ed25519;
use std::convert::TryFrom;

use ark_poly::{
    polynomial::univariate::DensePolynomial, polynomial::UVPolynomial,
    EvaluationDomain, Polynomial, Radix2EvaluationDomain,
};

use crate::dkg;
use crate::syncvss::params::Params;

type Scalar = Fr;

pub type ShareCiphertext = Vec<u8>;

pub struct Share {
    pub s: Vec<Scalar>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct DealtShares {
    pub tau: u32,
    pub d: u32,
    pub commitment: G1Affine,
    pub shares: Vec<ShareCiphertext>,
}

pub fn deal_shares<R: rand::Rng + rand::CryptoRng + Sized>(
    rng: &mut R,
    s: Scalar,
    dkg: &dkg::Context,
) -> Vec<u8> {
    let mut phi = DensePolynomial::<Scalar>::rand(dkg.params.t as usize, rng);
    phi.coeffs[0] = s;
    let evals = phi.evaluate_over_domain_by_ref(dkg.domain);

    let commitment = G1Affine::prime_subgroup_generator(); // Placeholder

    let vss_shares = dkg
        .participants
        .iter()
        .map(|participant| {
            encrypt(
                &evals.evals[participant.share_index
                    ..participant.share_index + participant.weight as usize],
                &G1Affine::prime_subgroup_generator(), // TODO: placeholder
                &participant.keys.encryption_key,
                &dkg.my_encryption_key,
            )
        })
        .collect::<Vec<ShareCiphertext>>();

    let mut msg_bytes = vec![];

    //msg_bytes.extend_from_slice(&dkg.tau.to_le_bytes());
    //msg_bytes.extend_from_slice(&dkg.my_index.to_le_bytes());
    //commitment.serialize(&mut msg_bytes);
    //vss_shares.serialize(&mut msg_bytes).unwrap(); // Placeholder
    let dealt_shares = DealtShares {
        tau: dkg.tau,
        d: dkg.my_index,
        commitment,
        shares: vss_shares,
    };
    dealt_shares.serialize(&mut msg_bytes);
    let signature = dkg.my_signature_key.sign(&msg_bytes);
    msg_bytes.extend_from_slice(&signature.to_bytes());
    msg_bytes
}

pub fn encrypt(
    shares: &[Scalar],
    opening: &G1Affine,
    public_key: &crypto_box::PublicKey,
    secret_key: &crypto_box::SecretKey,
) -> ShareCiphertext {
    let mut msg = vec![];
    shares.serialize(&mut msg);
    opening.serialize(&mut msg);

    let msg_box = crypto_box::ChaChaBox::new(&public_key, &secret_key);
    let mut rng = rand::thread_rng();
    let nonce = [0u8; 24]; //crypto_box::generate_nonce(&mut rng);

    msg_box.encrypt(&nonce.into(), &msg[..]).unwrap()
}

pub fn recv_dealing(
    dkg: &mut dkg::Context,
    shares: Vec<u8>,
) -> Result<(), String> {
    use blake2b_simd::{Params, State};
    use std::convert::TryInto;

    if shares.len() <= ed25519::SIGNATURE_LENGTH {
        return Err("too short".to_string());
    }
    let sig_bytes =
        &shares[shares.len() - ed25519::SIGNATURE_LENGTH..shares.len()];
    let msg_bytes = &shares[0..shares.len() - ed25519::SIGNATURE_LENGTH];

    let mut params = blake2b_simd::Params::new();
    params.hash_length(32);
    let mut hasher = params.to_state();
    hasher.update(&shares);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(hasher.finalize().as_bytes());

    let shares = DealtShares::deserialize(&shares[..]).unwrap(); //TODO: handle error

    if dkg.tau != shares.tau {
        return Ok(()); // not relevant round
    }

    if dkg.recv_shares.contains_key(&shares.d) {
        return Ok(());
    }

    let signature = Signature::try_from(sig_bytes).unwrap();
    dkg.participants[shares.d as usize]
        .keys
        .signing_key
        .verify_strict(msg_bytes, &signature)
        .unwrap();

    let enc_share = &shares.shares[dkg.my_index as usize];
    let dec_share = decrypt(
        &enc_share,
        &shares.commitment,
        dkg.participants[dkg.my_index as usize]
            .share_domain
            .as_ref()
            .unwrap(),
        &dkg.participants[shares.d as usize].keys.encryption_key,
        &dkg.my_encryption_key,
    )
    .unwrap();

    dkg.recv_dealings.insert(hash, shares);
    Ok(())
}

pub fn decrypt(
    enc_share: &[u8],
    commitment: &G1Affine,
    domain: &Vec<Scalar>,
    public_key: &crypto_box::PublicKey,
    secret_key: &crypto_box::SecretKey,
) -> Result<Vec<Scalar>, String> {
    let msg_box = crypto_box::ChaChaBox::new(&public_key, &secret_key);
    let mut rng = rand::thread_rng();
    let nonce = [0u8; 24]; //crypto_box::generate_nonce(&mut rng);

    let dec_share = msg_box.decrypt(&nonce.into(), enc_share);

    Ok(vec![])
}
