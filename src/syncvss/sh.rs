#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]
#![allow(unused_imports)]
#![allow(unused_variables)]

//use crate::poly;

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
use crate::syncvss::nizkp::NIZKP_BLS;
use ark_poly::{
    polynomial::univariate::DensePolynomial, polynomial::UVPolynomial,
    EvaluationDomain, Polynomial, Radix2EvaluationDomain,
};
use ed25519_dalek as ed25519;
use std::convert::TryFrom;

use crate::dkg;
use crate::syncvss::params::Params;

pub type Scalar = Fr;

pub type ShareCiphertext = Vec<u8>;

pub struct Share {
    pub s: Vec<Scalar>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct DealtShares {
    pub tau: u32,
    pub d: u32,
    pub commitment: G1Affine,
    pub secret_commitment: G1Affine,
    pub opening_proof: G1Affine,
    pub shares: Vec<ShareCiphertext>,
}

//#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct FinalizeMsg {
    //pub rebased_secret: G1Affine,
//  pub proof: NIZKP_BLS,
}

pub fn deal_shares<R: rand::Rng + rand::CryptoRng + Sized>(
    rng: &mut R,
    s: Scalar,
    dkg: &dkg::Context,
) -> (Vec<u8>, FinalizeMsg) {
    let mut phi = DensePolynomial::<Scalar>::rand(dkg.params.t as usize, rng);
    phi.coeffs[0] = s;
    let evals = phi.evaluate_over_domain_by_ref(dkg.domain);

    let commitment = G1Affine::prime_subgroup_generator(); // TODO: Placeholder

    let secret_commitment = G1Affine::prime_subgroup_generator().mul(s);

    let opening_proof = G1Affine::prime_subgroup_generator(); // TODO: Placeholder

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
        secret_commitment: secret_commitment.into(),
        opening_proof,
        shares: vss_shares,
    };
    dealt_shares.serialize(&mut msg_bytes).unwrap();
    let signature = dkg.my_signature_key.sign(&msg_bytes);
    msg_bytes.extend_from_slice(&signature.to_bytes());
    (msg_bytes, FinalizeMsg {})
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct NodeSharesPlaintext {
    pub shares: Vec<Scalar>,
    pub opening: G1Affine,
}

pub fn encrypt(
    shares: &[Scalar],
    opening: &G1Affine,
    public_key: &crypto_box::PublicKey,
    secret_key: &crypto_box::SecretKey,
) -> ShareCiphertext {
    let mut msg = vec![];
    NodeSharesPlaintext {
        shares: shares.to_vec(),
        opening: *opening,
    }
    .serialize(&mut msg)
    .unwrap();
    //opening.serialize(&mut msg);

    let msg_box = crypto_box::ChaChaBox::new(&public_key, &secret_key);
    //let mut rng = rand::thread_rng();
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
    //let mut rng = rand::thread_rng();
    let nonce = [0u8; 24]; //crypto_box::generate_nonce(&mut rng);

    let dec_share = msg_box.decrypt(&nonce.into(), enc_share).unwrap();

    let node_shares = NodeSharesPlaintext::deserialize(&dec_share[..]).unwrap();

    //TODO: Check node_shares.opening

    Ok(node_shares.shares)
}

pub fn finalize_vss() {}

#[test]
fn test_encrypt_decrypt() {
    use rand_chacha::rand_core::{RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    let mut rng = rand::thread_rng();
    //let mut rng = ChaCha8Rng::from_seed([0u8;32]);
    use ark_std::UniformRand;
    use crypto_box::{PublicKey, SecretKey};

    for _ in 0..1000 {
        let alice_secret = SecretKey::generate(&mut rng);

        let alice_public = PublicKey::from(&alice_secret);
        let bob_secret = SecretKey::generate(&mut rng);

        let bob_public = PublicKey::from(&bob_secret);

        let mut sent_shares = vec![];
        for _ in 0..1000 {
            sent_shares.push(Scalar::rand(&mut rng));
        }

        let enc = encrypt(
            sent_shares.as_slice(),
            &G1Affine::prime_subgroup_generator(),
            &bob_public,
            &alice_secret,
        );

        let domain = vec![Scalar::zero(); 1000]; //TODO: real domain

        let dec = decrypt(
            &enc,
            &G1Affine::prime_subgroup_generator(),
            &domain,
            &alice_public,
            &bob_secret,
        )
        .unwrap();
    }
}
