#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]
//#![allow(unused_imports)]
#![allow(unused_variables)]

//use crate::poly;
//use crate::signed_data;

use crate::syncvss::nizkp::NIZKP_BLS;
use ark_bls12_381::{Fr, G1Affine};
use ark_ec::AffineCurve;
use ark_poly::{
    polynomial::univariate::DensePolynomial,
    polynomial::UVPolynomial,
    //    EvaluationDomain, Polynomial, Radix2EvaluationDomain,
};
use ark_serialize::CanonicalSerialize;
use ark_serialize::*;
use chacha20poly1305::aead::Aead;
//use crypto_box::aead::Aead;
//use ed25519_dalek as ed25519;
//use ed25519_dalek::Signature;
//use ed25519_dalek::Signer;
//use either::Either;
//use num::integer::div_ceil;
//use num::Zero;
//use std::collections::{HashMap, HashSet};
//use std::convert::TryFrom;
//use std::rc::Rc;

use crate::dkg;
//use crate::syncvss::dh;
//use crate::syncvss::params::Params;
use serde::{Deserialize, Serialize};

pub type Scalar = Fr;

pub type ShareCiphertext = Vec<u8>;

pub enum State {
    Sharing { weight_ready: u32 },
    Success { final_secret: G1Affine },
    Failure,
}

pub struct Context {
    pub dealer: u32,
    pub encrypted_shares: EncryptedShares,
    pub state: State,
    pub local_shares: Vec<Scalar>,
    pub ready_msg: Vec<ed25519_dalek::PublicKey>, //TODO: Should be a set, but doesn't support comparison ops
    pub finalize_msg: Option<FinalizeMsg>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EncryptedShares {
    #[serde(with = "crate::ark_serde")]
    pub commitment: G1Affine,

    #[serde(with = "crate::ark_serde")]
    pub secret_commitment: G1Affine,

    #[serde(with = "crate::ark_serde")]
    pub opening_proof: G1Affine,
    pub shares: Vec<ShareCiphertext>,
}

//TODO: Is the entire ready message necessary at all or do we just have a dispute timeout?
#[derive(Serialize, Deserialize, Copy, Clone)]
pub struct ReadyMsg {
    pub dealer: u32,

    #[serde(with = "crate::ark_serde")]
    pub commitment: G1Affine, //TODO: necessary?
}

#[derive(Serialize, Deserialize, Copy, Clone)]
pub struct FinalizeMsg {
    #[serde(with = "crate::ark_serde")]
    pub rebased_secret: G1Affine,
    pub proof: NIZKP_BLS,
}

impl Context {
    pub fn handle_ready(
        &mut self,
        signer: &ed25519_dalek::PublicKey,
        ready: &ReadyMsg,
        signer_weight: u32,
    ) -> Result<u32, anyhow::Error> {
        if let State::Sharing { weight_ready } = self.state {
            if ready.commitment == self.encrypted_shares.commitment {
                if self.ready_msg.contains(&signer) {
                    return Err(anyhow::anyhow!("Duplicate ready message"));
                } else {
                    self.ready_msg.push(*signer);
                    self.state = State::Sharing {
                        weight_ready: weight_ready + signer_weight,
                    };
                    return Ok(weight_ready + signer_weight);
                }
            } else {
                return Err(anyhow::anyhow!(
                    "ReadyMsg: Wrong commitment for dealer"
                ));
            }
        }
        Ok(0u32) //TODO: better return possible?
    }

    pub fn handle_finalize(
        &mut self,
        finalize: &FinalizeMsg,
        minimum_ready_weight: u32,
    ) -> Result<(), anyhow::Error> {
        if let State::Sharing { weight_ready } = self.state {
            if weight_ready >= minimum_ready_weight {
                if finalize.proof.dleq_verify(
                    &G1Affine::prime_subgroup_generator(),
                    &self.encrypted_shares.secret_commitment,
                    &G1Affine::prime_subgroup_generator(),
                    &finalize.rebased_secret,
                ) {
                    self.state = State::Success {
                        final_secret: finalize.rebased_secret,
                    };
                    return Ok(());
                } else {
                    return Err(anyhow::anyhow!(
                        "FinalizeMsg: bad rebased secret proof"
                    ));
                }
            } else {
                return Err(anyhow::anyhow!("FinalizeMsg: dealer was early"));
            }
        } else {
            Err(anyhow::anyhow!("FinalizeMsg: not currently sharing"))
        }
    }
    pub fn new_send<R: rand::Rng + rand::CryptoRng + Sized>(
        s: &Scalar,
        dkg: &dkg::Context,
        rng: &mut R,
    ) -> Context {
        let mut phi = DensePolynomial::<Scalar>::rand(
            dkg.params.security_threshold as usize,
            rng,
        );
        phi.coeffs[0] = *s;

        let evals = phi.evaluate_over_domain_by_ref(dkg.domain);
        let commitment = G1Affine::prime_subgroup_generator(); // TODO: Placeholder
        let secret_commitment =
            G1Affine::prime_subgroup_generator().mul(*s).into();
        let opening_proof = G1Affine::prime_subgroup_generator(); // TODO: Placeholder

        let shares = dkg
            .participants
            .iter()
            .map(|participant| {
                if participant.ed_key == dkg.ed_key.public {
                    vec![]
                } else {
                    encrypt(
                        &evals.evals[participant.share_range.clone()],
                        &G1Affine::prime_subgroup_generator(), // TODO: placeholder
                        &dkg.dh_key.encrypt_cipher(&participant.dh_key),
                    )
                }
            })
            .collect::<Vec<ShareCiphertext>>();

        //phi.zeroize(); // TODO zeroize?

        let rebased_secret =
            G1Affine::prime_subgroup_generator().mul(*s).into(); //TODO: new base
        let proof = NIZKP_BLS::dleq(
            &G1Affine::prime_subgroup_generator(),
            &rebased_secret,
            &G1Affine::prime_subgroup_generator(),
            &rebased_secret,
            &s,
            rng,
        );
        let vss = Context {
            dealer: dkg.me as u32,
            encrypted_shares: EncryptedShares {
                commitment,
                secret_commitment,
                opening_proof,
                shares,
            },
            state: State::Sharing { weight_ready: 0u32 },
            local_shares: evals.evals
                [dkg.participants[dkg.me].share_range.clone()]
            .to_vec(),
            finalize_msg: Some(FinalizeMsg {
                rebased_secret,
                proof,
            }),
            ready_msg: vec![],
        };

        vss
    }
    pub fn new_recv(
        dealer: u32,
        encrypted_shares: &EncryptedShares,
        dkg: &mut dkg::Context,
    ) -> Result<Context, anyhow::Error> {
        let encrypted_local_shares = &encrypted_shares.shares[dkg.me as usize];
        let local_shares = decrypt(
            &encrypted_local_shares,
            &encrypted_shares.commitment,
            &dkg.participants[dkg.me as usize].share_domain,
            &dkg.dh_key
                .decrypt_cipher(&dkg.participants[dealer as usize].dh_key),
        )?;
        Ok(Context {
            dealer,
            encrypted_shares: encrypted_shares.clone(),
            state: State::Sharing { weight_ready: 0u32 },
            local_shares,
            finalize_msg: None,
            ready_msg: vec![],
        })
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct NodeSharesPlaintext {
    pub shares: Vec<Scalar>,
    pub opening: G1Affine,
}

pub fn encrypt(
    shares: &[Scalar],
    opening: &G1Affine,
    cipher: &chacha20poly1305::XChaCha20Poly1305,
) -> ShareCiphertext {
    let mut msg = vec![];
    NodeSharesPlaintext {
        shares: shares.to_vec(),
        opening: *opening,
    }
    .serialize(&mut msg)
    .unwrap();

    let nonce = [0u8; 24]; //TODO: add nonce?
    cipher.encrypt(&nonce.into(), &msg[..]).unwrap()
}

pub fn decrypt(
    enc_share: &[u8],
    commitment: &G1Affine,
    domain: &[Scalar],
    cipher: &chacha20poly1305::XChaCha20Poly1305,
) -> Result<Vec<Scalar>, anyhow::Error> {
    let nonce = [0u8; 24]; //TODO: add nonce?

    let dec_share = cipher.decrypt(&nonce.into(), enc_share).unwrap(); // TODO: handle ?;

    let node_shares = NodeSharesPlaintext::deserialize(&dec_share[..])?;
    //TODO: Check node_shares.opening

    Ok(node_shares.shares)
}

pub fn finalize_vss() -> FinalizeMsg {
    unimplemented!()
}

#[test]
fn test_encrypt_decrypt() {
    use rand_chacha::rand_core::{RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    let mut rng = rand::thread_rng();
    //let mut rng = ChaCha8Rng::from_seed([0u8;32]);
    use crate::syncvss::dh;
    use ark_ff::Zero;
    use ark_std::UniformRand;

    for _ in 0..1000 {
        let alice_secret = dh::AsymmetricKeypair::new(&mut rng); //SecretKey::generate(&mut rng);

        let alice_public = alice_secret.public();
        let bob_secret = dh::AsymmetricKeypair::new(&mut rng);

        let bob_public = bob_secret.public();

        let mut sent_shares = vec![];
        for _ in 0..1000 {
            sent_shares.push(Scalar::rand(&mut rng));
        }

        let enc = encrypt(
            sent_shares.as_slice(),
            &G1Affine::prime_subgroup_generator(),
            &alice_secret.encrypt_cipher(&bob_public),
        );

        let domain = vec![Scalar::zero(); 1000]; //TODO: real domain

        let dec = decrypt(
            &enc,
            &G1Affine::prime_subgroup_generator(),
            &domain,
            &bob_secret.decrypt_cipher(&alice_public),
        )
        .unwrap();
    }
}
