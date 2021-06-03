#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]

use crate::{dkg, fastkzg, fastpoly, Scalar};

use crate::syncvss::nizkp::NIZKP_BLS;
use ark_bls12_381::G1Affine;
use ark_ec::AffineCurve;
use ark_poly::{
    polynomial::univariate::DensePolynomial,
    polynomial::UVPolynomial,
    //    EvaluationDomain, Polynomial, Radix2EvaluationDomain,
};
use ark_serialize::CanonicalSerialize;
use ark_serialize::*;
use chacha20poly1305::aead::Aead;

use serde::{Deserialize, Serialize};

#[cfg(feature = "borsh")]
use ark_serialize::CanonicalDeserialize;
#[cfg(feature = "borsh")]
use borsh::maybestd::io as borsh_io;
#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

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
    pub zero_opening: G1Affine,
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
    //TODO: necessary?
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
        g: &G1Affine,
    ) -> Result<(), anyhow::Error> {
        if let State::Sharing { weight_ready } = self.state {
            if weight_ready >= minimum_ready_weight {
                if finalize.proof.dleq_verify(
                    &g,
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
    ) -> Result<Context, anyhow::Error> {
        use ark_ec::msm::VariableBaseMSM;
        let mut phi = DensePolynomial::<Scalar>::rand(
            dkg.params.security_threshold as usize,
            rng,
        );
        phi.coeffs[0] = *s;

        let evals = phi.evaluate_over_domain_by_ref(dkg.domain);
        let commitment = crate::fastkzg::g1_commit(&dkg.powers_of_g, &phi)?; //G1Affine::prime_subgroup_generator(); // TODO: Placeholder
        let secret_commitment = dkg.powers_of_g[0].mul(*s).into();

        let zero_opening = VariableBaseMSM::multi_scalar_mul(
            &dkg.powers_of_g[0..],
            &crate::fastkzg::convert_to_bigints(&phi.coeffs[1..]),
        )
        .into();

        let opening_proofs = crate::fastkzg::AmortizedOpeningProof::new(
            &dkg.powers_of_g,
            &phi,
            &dkg.domain,
        )?;

        let shares = dkg
            .participants
            .iter()
            .map(|participant| {
                if participant.ed_key == dkg.ed_key.public {
                    vec![]
                } else {
                    let local_evals =
                        &evals.evals[participant.share_range.clone()];
                    let opening = opening_proofs.combine(
                        &participant.share_range,
                        local_evals,
                        &participant.share_domain,
                    );
                    encrypt(
                        &local_evals,
                        &opening,
                        &dkg.dh_key.encrypt_cipher(&participant.dh_key),
                    )
                }
            })
            .collect::<Vec<ShareCiphertext>>();

        //phi.zeroize(); // TODO zeroize?

        let rebased_secret =
            G1Affine::prime_subgroup_generator().mul(*s).into(); //TODO: new base
        let proof = NIZKP_BLS::dleq(
            &dkg.powers_of_g[0],
            &secret_commitment,
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
                zero_opening,
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

        Ok(vss)
    }
    pub fn new_recv(
        dealer: u32,
        encrypted_shares: &EncryptedShares,
        dkg: &mut dkg::Context,
    ) -> Result<Context, anyhow::Error> {
        use ark_ec::PairingEngine;
        let me = &dkg.participants[dkg.me as usize];

        let encrypted_local_shares = &encrypted_shares.shares[dkg.me as usize];

        let comm = encrypted_shares.commitment.into_projective()
            - encrypted_shares.secret_commitment.into_projective();
        if crate::Curve::pairing(comm, dkg.powers_of_h[0])
            != crate::Curve::pairing(encrypted_shares.zero_opening, dkg.beta_h)
        {
            return Err(anyhow::anyhow!("bad zero opening"));
        }

        let local_shares = decrypt(
            &encrypted_local_shares,
            &dkg.dh_key
                .decrypt_cipher(&dkg.participants[dealer as usize].dh_key),
        )?;
        let evaluation_polynomial =
            me.share_domain.fast_interpolate(&local_shares.shares);

        let evaluation_polynomial_commitment =
            fastkzg::g1_commit(&dkg.powers_of_g, &evaluation_polynomial)?;
        if !fastkzg::check_batched(
            &dkg.powers_of_h,
            &encrypted_shares.commitment,
            &me.domain_commitment.ok_or_else(|| {
                anyhow::anyhow!("my domain_commitment not computed")
            })?,
            &evaluation_polynomial_commitment,
            &local_shares.opening,
        )? {
            return Err(anyhow::anyhow!("share opening proof invalid"));
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
    cipher: &chacha20poly1305::XChaCha20Poly1305,
) -> Result<NodeSharesPlaintext, anyhow::Error> {
    let nonce = [0u8; 24]; //TODO: add nonce?

    let dec_share = cipher.decrypt(&nonce.into(), enc_share).unwrap(); //TODO: implement StdError for aead::error

    let node_shares = NodeSharesPlaintext::deserialize(&dec_share[..])?;

    Ok(node_shares)
}

#[test]
fn test_encrypt_decrypt() {
    //use rand_chacha::rand_core::{RngCore, SeedableRng};
    //use rand_chacha::ChaCha8Rng;

    let rng = &mut ark_std::test_rng();
    use crate::syncvss::dh;
    use ark_ff::Zero;
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
            &G1Affine::prime_subgroup_generator(),
            &alice_secret.encrypt_cipher(&bob_public),
        );

        let domain = vec![Scalar::zero(); 1000]; //TODO: real domain

        let dec =
            decrypt(&enc, &bob_secret.decrypt_cipher(&alice_public)).unwrap();
    }
}

#[cfg(feature = "borsh")]
fn ark_to_bytes<T: CanonicalSerialize>(value: T) -> Vec<u8> {
    let mut bytes = vec![0u8; value.serialized_size()];
    value.serialize(&mut bytes).expect("failed to serialize");
    bytes
}

#[cfg(feature = "borsh")]
fn ark_from_bytes<T: CanonicalDeserialize>(bytes: &[u8]) -> Option<T> {
    CanonicalDeserialize::deserialize(bytes).ok()
}

#[cfg(feature = "borsh")]
impl BorshSerialize for State {
    fn serialize<W: borsh_io::Write>(
        &self,
        writer: &mut W,
    ) -> borsh_io::Result<()> {
        match self {
            State::Sharing { weight_ready } => {
                BorshSerialize::serialize(&0u8, writer)?;
                BorshSerialize::serialize(weight_ready, writer)
            }
            State::Success { final_secret } => {
                BorshSerialize::serialize(&1u8, writer)?;
                BorshSerialize::serialize(&ark_to_bytes(*final_secret), writer)
            }
            State::Failure => BorshSerialize::serialize(&2u8, writer),
        }
    }
}

#[cfg(feature = "borsh")]
impl BorshDeserialize for State {
    fn deserialize(buf: &mut &[u8]) -> borsh_io::Result<Self> {
        let tag: u8 = BorshDeserialize::deserialize(buf)?;
        match tag {
            0u8 => {
                let weight_ready = BorshDeserialize::deserialize(buf)?;
                Ok(State::Sharing { weight_ready })
            }
            1u8 => {
                let final_secret: Vec<u8> = BorshDeserialize::deserialize(buf)?;
                let final_secret = ark_from_bytes(&final_secret)
                    .expect("failed to deserialize");
                Ok(State::Success { final_secret })
            }
            2u8 => Ok(State::Failure),
            _ => Err(borsh_io::ErrorKind::InvalidData.into()),
        }
    }
}

#[cfg(feature = "borsh")]
impl BorshSerialize for Context {
    fn serialize<W: borsh_io::Write>(
        &self,
        writer: &mut W,
    ) -> borsh_io::Result<()> {
        let local_shares: Vec<_> = self
            .local_shares
            .iter()
            .cloned()
            .map(ark_to_bytes)
            .collect();
        let ready_msg: Vec<_> = self
            .ready_msg
            .iter()
            .cloned()
            .map(|pk| pk.to_bytes())
            .collect();
        BorshSerialize::serialize(
            &(
                &self.dealer,
                &self.encrypted_shares,
                &self.state,
                &local_shares,
                &ready_msg,
                &self.finalize_msg,
            ),
            writer,
        )
    }
}

#[cfg(feature = "borsh")]
impl BorshDeserialize for Context {
    fn deserialize(buf: &mut &[u8]) -> borsh_io::Result<Self> {
        let (
            dealer,
            encrypted_shares,
            state,
            local_shares,
            ready_msg,
            finalize_msg,
        ): (
            u32,
            EncryptedShares,
            State,
            Vec<Vec<u8>>,
            Vec<Vec<u8>>,
            Option<FinalizeMsg>,
        ) = BorshDeserialize::deserialize(buf)?;
        let local_shares: Vec<_> = local_shares
            .iter()
            .map(|bytes| ark_from_bytes(bytes).expect("failed to deserialize"))
            .collect();
        let ready_msg: Vec<_> = ready_msg
            .iter()
            .map(|bytes| {
                ed25519_dalek::PublicKey::from_bytes(bytes)
                    .expect("failed to deserialize")
            })
            .collect();
        Ok(Self {
            dealer,
            encrypted_shares,
            state,
            local_shares,
            ready_msg,
            finalize_msg,
        })
    }
}

#[cfg(feature = "borsh")]
impl BorshSerialize for EncryptedShares {
    fn serialize<W: borsh_io::Write>(
        &self,
        writer: &mut W,
    ) -> borsh_io::Result<()> {
        let commitment = ark_to_bytes(self.commitment);
        let secret_commitment = ark_to_bytes(self.secret_commitment);
        let zero_opening = ark_to_bytes(self.zero_opening);
        let shares = &self.shares;
        BorshSerialize::serialize(
            &(commitment, secret_commitment, zero_opening, shares),
            writer,
        )
    }
}

#[cfg(feature = "borsh")]
impl BorshDeserialize for EncryptedShares {
    fn deserialize(buf: &mut &[u8]) -> borsh_io::Result<Self> {
        let (commitment, secret_commitment, zero_opening, shares): (
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<ShareCiphertext>,
        ) = BorshDeserialize::deserialize(buf)?;
        let commitment =
            ark_from_bytes(&commitment).expect("failed to deserialize");
        let secret_commitment =
            ark_from_bytes(&secret_commitment).expect("failed to deserialize");
        let zero_opening =
            ark_from_bytes(&zero_opening).expect("failed to deserialize");
        Ok(Self {
            commitment,
            secret_commitment,
            zero_opening,
            shares,
        })
    }
}

#[cfg(feature = "borsh")]
impl BorshSerialize for ReadyMsg {
    fn serialize<W: borsh_io::Write>(
        &self,
        writer: &mut W,
    ) -> borsh_io::Result<()> {
        let commitment = ark_to_bytes(self.commitment);
        BorshSerialize::serialize(&(self.dealer, commitment), writer)
    }
}

#[cfg(feature = "borsh")]
impl BorshDeserialize for ReadyMsg {
    fn deserialize(buf: &mut &[u8]) -> borsh_io::Result<Self> {
        let (dealer, commitment): (u32, Vec<u8>) =
            BorshDeserialize::deserialize(buf)?;
        let commitment =
            ark_from_bytes(&commitment).expect("failed to deserialize");
        Ok(Self { dealer, commitment })
    }
}

#[cfg(feature = "borsh")]
impl BorshSerialize for FinalizeMsg {
    fn serialize<W: borsh_io::Write>(
        &self,
        writer: &mut W,
    ) -> borsh_io::Result<()> {
        let rebased_secret = ark_to_bytes(self.rebased_secret);
        BorshSerialize::serialize(&(rebased_secret, self.proof), writer)
    }
}

#[cfg(feature = "borsh")]
impl BorshDeserialize for FinalizeMsg {
    fn deserialize(buf: &mut &[u8]) -> borsh_io::Result<Self> {
        let (rebased_secret, proof): (Vec<u8>, NIZKP_BLS) =
            BorshDeserialize::deserialize(buf)?;
        let rebased_secret =
            ark_from_bytes(&rebased_secret).expect("failed to deserialize");
        Ok(Self {
            rebased_secret,
            proof,
        })
    }
}
