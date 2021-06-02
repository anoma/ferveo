#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]

use crate::{dkg, Affine, Projective, Scalar};

use crate::syncvss::nizkp::NIZKP_Pallas;
use ark_ec::msm::FixedBaseMSM;
use ark_ec::AffineCurve;
use ark_ec::ProjectiveCurve;
use ark_ff::PrimeField;
use ark_poly::{
    polynomial::univariate::DensePolynomial,
    polynomial::UVPolynomial,
    //    EvaluationDomain, Polynomial, Radix2EvaluationDomain,
};
use ark_serialize::*;
use chacha20poly1305::aead::Aead;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct ShareCiphertext {
    pub ciphertext: Vec<u8>,
}

/// The possible States of a VSS instance
pub enum State {
    /// The VSS is currently in a Sharing state with weight_ready
    /// of participants signaling Ready for this VSS
    Sharing { weight_ready: u32 },
    /// The VSS has completed Successfully with final secret commitment g^{\phi(0)}
    Success { final_secret: Affine },
    /// The VSS has ended in Failure
    Failure,
}

/// The Context of an individual VSS instance as either the Dealer or the Dealee
pub struct Context {
    pub dealer: u32,
    pub encrypted_shares: EncryptedShares,
    pub state: State,
    pub local_shares: Vec<Scalar>,
    pub ready_msg: Vec<ed25519_dalek::PublicKey>, //TODO: Should be a set, but doesn't support comparison ops
    pub finalize_msg: Option<FinalizeMsg>,
}

/// The dealer posts the EncryptedShares to the blockchain to initiate the VSS
#[derive(Serialize, Deserialize, Clone)]
pub struct EncryptedShares {
    /// Commitment to the VSS polynomial, g^{\phi}
    #[serde(with = "crate::ark_serde")]
    pub commitment: Vec<Affine>,

    /// The encrypted shares for each participant
    pub shares: Vec<ShareCiphertext>,
}

//TODO: Is the entire ready message necessary at all or do we just have a dispute timeout?
#[derive(Serialize, Deserialize, Copy, Clone)]
pub struct ReadyMsg {
    pub dealer: u32,
}

#[derive(Serialize, Deserialize, Copy, Clone)]
pub struct FinalizeMsg {
    //TODO: necessary?
    #[serde(with = "crate::ark_serde")]
    pub rebased_secret: Affine,
    pub proof: NIZKP_Pallas,
}

impl Context {
    pub fn handle_ready(
        &mut self,
        signer: &ed25519_dalek::PublicKey,
        ready: &ReadyMsg,
        signer_weight: u32,
    ) -> Result<u32, anyhow::Error> {
        if let State::Sharing { weight_ready } = self.state {
            if self.ready_msg.contains(&signer) {
                return Err(anyhow::anyhow!("Duplicate ready message"));
            } else {
                self.ready_msg.push(*signer);
                self.state = State::Sharing {
                    weight_ready: weight_ready + signer_weight,
                };
                return Ok(weight_ready + signer_weight);
            }
        }
        Ok(0u32) //TODO: better return possible?
    }

    pub fn handle_finalize(
        &mut self,
        finalize: &FinalizeMsg,
        minimum_ready_weight: u32,
        g: &Affine,
    ) -> Result<(), anyhow::Error> {
        if let State::Sharing { weight_ready } = self.state {
            if weight_ready >= minimum_ready_weight {
                if finalize.proof.dleq_verify(
                    &g,
                    &self.encrypted_shares.commitment[0],
                    &Affine::prime_subgroup_generator(),
                    &finalize.rebased_secret,
                ) {
                    self.state = State::Success {
                        final_secret: finalize.rebased_secret,
                    };
                    Ok(())
                } else {
                    Err(anyhow::anyhow!(
                        "FinalizeMsg: bad rebased secret proof"
                    ))
                }
            } else {
                Err(anyhow::anyhow!("FinalizeMsg: dealer was early"))
            }
        } else {
            Err(anyhow::anyhow!("FinalizeMsg: not currently sharing"))
        }
    }
    pub fn new_send<R: rand::Rng + rand::CryptoRng + Sized>(
        s: &Scalar,
        dkg: &dkg::Context,
        rng: &mut R,
    ) -> Result<Context, anyhow::Error> {
        use ark_poly::Polynomial;
        let mut phi = DensePolynomial::<Scalar>::rand(
            dkg.params.security_threshold as usize,
            rng,
        );
        phi.coeffs[0] = *s;

        let evals = phi.evaluate_over_domain_by_ref(dkg.domain);
        let window_size = FixedBaseMSM::get_mul_window_size(phi.degree() + 1);

        let scalar_bits = Scalar::size_in_bits();
        let g_table = FixedBaseMSM::get_window_table(
            scalar_bits,
            window_size,
            Affine::prime_subgroup_generator().into_projective(),
        );
        let commitment = FixedBaseMSM::multi_scalar_mul::<Projective>(
            scalar_bits,
            window_size,
            &g_table,
            &phi.coeffs,
        );
        let commitment =
            Projective::batch_normalization_into_affine(&commitment);

        let shares = dkg
            .participants
            .iter()
            .filter_map(|participant| {
                if participant.ed_key == dkg.ed_key.public {
                    None
                } else {
                    let local_evals =
                        &evals.evals[participant.share_range.clone()];

                    Some(encrypt(
                        &local_evals,
                        &dkg.dh_key.encrypt_cipher(&participant.dh_key),
                    ))
                }
            })
            .collect::<Vec<ShareCiphertext>>();

        //phi.zeroize(); // TODO zeroize?

        let rebased_secret = Affine::prime_subgroup_generator().mul(*s).into(); //TODO: new base
        let proof = NIZKP_Pallas::dleq(
            &Affine::prime_subgroup_generator(),
            &commitment[0],
            &Affine::prime_subgroup_generator(),
            &rebased_secret,
            &s,
            rng,
        );
        let vss = Context {
            dealer: dkg.me as u32,
            encrypted_shares: EncryptedShares { commitment, shares },
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

        Ok(vss)
    }
    pub fn new_recv(
        dealer: u32,
        encrypted_shares: &EncryptedShares,
        dkg: &mut dkg::Context,
    ) -> Result<Context, anyhow::Error> {
        use ark_poly::EvaluationDomain;
        let me = &dkg.participants[dkg.me as usize];

        if encrypted_shares.shares.len() != dkg.participants.len() - 1 {
            return Err(anyhow::anyhow!("wrong vss length"));
        }
        let adjusted_index =
            dkg.me - if dkg.me > dealer as usize { 1 } else { 0 };

        let encrypted_local_shares = &encrypted_shares.shares[adjusted_index];

        let local_shares = decrypt(
            &encrypted_local_shares,
            &dkg.dh_key
                .decrypt_cipher(&dkg.participants[dealer as usize].dh_key),
        )?;

        let mut commitment = encrypted_shares
            .commitment
            .iter()
            .map(|p| p.into_projective())
            .collect::<Vec<_>>();
        dkg.domain.fft_in_place(&mut commitment);

        let commitment =
            Projective::batch_normalization_into_affine(&commitment);

        let window_size =
            FixedBaseMSM::get_mul_window_size(commitment.len() + 1);

        let scalar_bits = Scalar::size_in_bits();
        let g_table = FixedBaseMSM::get_window_table(
            scalar_bits,
            window_size,
            Affine::prime_subgroup_generator().into_projective(),
        );
        let shares_commitment = FixedBaseMSM::multi_scalar_mul::<Projective>(
            scalar_bits,
            window_size,
            &g_table,
            &local_shares.shares,
            //&dkg.participants[dkg.me].share_domain,
        );
        let shares_commitment =
            Projective::batch_normalization_into_affine(&shares_commitment);

        for (i, j) in commitment[dkg.participants[dkg.me].share_range.clone()]
            .iter()
            .zip(shares_commitment.iter())
        {
            if *i != *j {
                return Err(anyhow::anyhow!("share opening proof invalid"));
            }
        }

        Ok(Context {
            dealer,
            encrypted_shares: encrypted_shares.clone(),
            state: State::Sharing { weight_ready: 0u32 },
            local_shares: local_shares.shares,
            finalize_msg: None,
            ready_msg: vec![],
        })
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct NodeSharesPlaintext {
    pub shares: Vec<Scalar>,
}

pub fn encrypt(
    shares: &[Scalar],
    cipher: &chacha20poly1305::XChaCha20Poly1305,
) -> ShareCiphertext {
    let mut msg = vec![];
    NodeSharesPlaintext {
        shares: shares.to_vec(),
    }
    .serialize(&mut msg)
    .unwrap();

    let nonce = [0u8; 24]; //TODO: add nonce?
    ShareCiphertext {
        ciphertext: cipher.encrypt(&nonce.into(), &msg[..]).unwrap(),
    }
}

pub fn decrypt(
    enc_share: &ShareCiphertext,
    cipher: &chacha20poly1305::XChaCha20Poly1305,
) -> Result<NodeSharesPlaintext, anyhow::Error> {
    let nonce = [0u8; 24]; //TODO: add nonce?

    let dec_share = cipher
        .decrypt(&nonce.into(), &enc_share.ciphertext[..])
        .unwrap(); //TODO: implement StdError for aead::error

    let node_shares = NodeSharesPlaintext::deserialize(&dec_share[..])?;

    Ok(node_shares)
}

#[test]
fn test_encrypt_decrypt() {
    let rng = &mut ark_std::test_rng();
    use crate::syncvss::dh;
    use ark_std::UniformRand;

    for _ in 0..1000 {
        let alice_secret = dh::AsymmetricKeypair::new(rng); //SecretKey::generate(&mut rng);

        let alice_public = alice_secret.public();
        let bob_secret = dh::AsymmetricKeypair::new(rng);

        let bob_public = bob_secret.public();

        let mut sent_shares = vec![];
        for _ in 0..1000 {
            sent_shares.push(Scalar::rand(rng));
        }

        let enc = encrypt(
            sent_shares.as_slice(),
            &alice_secret.encrypt_cipher(&bob_public),
        );

        //let domain = vec![Scalar::zero(); 1000]; //TODO: real domain

        let _dec =
            decrypt(&enc, &bob_secret.decrypt_cipher(&alice_public)).unwrap();
    }
}
