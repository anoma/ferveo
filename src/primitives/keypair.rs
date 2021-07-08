use crate::*;
use chacha20poly1305::aead::{generic_array::GenericArray, Aead, NewAead};

use ark_ec::PairingEngine;

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct PubliclyVerifiablePublicKey<E>
where
    E: PairingEngine,
{
    #[serde(with = "crate::ark_serde")]
    pub encryption_key: E::G2Affine,
}

#[derive(Clone)]
pub struct PubliclyVerifiableKeypair<E>
where
    E: PairingEngine,
{
    pub decryption_key: E::Fr,
}

impl<E> PubliclyVerifiableKeypair<E>
where
    E: PairingEngine,
{
    pub fn public(&self) -> PubliclyVerifiablePublicKey<E> {
        PubliclyVerifiablePublicKey::<E> {
            encryption_key: E::G2Affine::prime_subgroup_generator()
                .mul(self.decryption_key)
                .into_affine(),
        }
    }

    pub fn new<R: Rng>(rng: &mut R) -> Self {
        use ark_std::UniformRand;
        Self {
            decryption_key: E::Fr::rand(rng),
        }
    }
}
