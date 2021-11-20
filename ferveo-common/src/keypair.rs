use ark_ec::PairingEngine;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write,
};
use serde::*;

#[derive(Copy, Clone, Debug)]
pub struct PreparedPublicKey<E: PairingEngine> {
    pub encryption_key: E::G2Prepared,
}

impl<E: PairingEngine> From<PublicKey<E>> for PreparedPublicKey<E> {
    fn from(value: PublicKey<E>) -> Self {
        PreparedPublicKey::<E> {
            encryption_key: E::G2Prepared::from(value.encryption_key),
        }
    }
}

#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Serialize,
    Deserialize,
    CanonicalSerialize,
    CanonicalDeserialize,
)]
pub struct PublicKey<E: PairingEngine> {
    #[serde(with = "crate::ark_serde")]
    pub encryption_key: E::G2Affine,
}

impl<E: PairingEngine> Default for PublicKey<E> {
    fn default() -> Self {
        Self {
            encryption_key: E::G2Affine::prime_subgroup_generator(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Keypair<E: PairingEngine> {
    #[serde(with = "crate::ark_serde")]
    pub decryption_key: E::Fr,
}

impl<E: PairingEngine> Keypair<E> {
    /// Returns the public session key for the publicly verifiable DKG participant
    pub fn public(&self) -> PublicKey<E> {
        PublicKey::<E> {
            encryption_key: E::G2Affine::prime_subgroup_generator()
                .mul(self.decryption_key)
                .into_affine(),
        }
    }

    /// Creates a new ephemeral session key for participating in the DKG
    pub fn new<R: crate::Rng>(rng: &mut R) -> Self {
        use ark_std::UniformRand;
        Self {
            decryption_key: E::Fr::rand(rng),
        }
    }
}
