use anyhow::{anyhow, Result};
use ark_ec::PairingEngine;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write,
};

pub mod keypair;
pub use keypair::*;

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Validator<E: PairingEngine> {
    pub key: ValidatorPublicKey<E>,
    pub weight: u32,
    pub share_start: usize,
    pub share_end: usize,
}

impl<E: PairingEngine> Validator<E> {
    pub fn encryption_key(&self) -> Result<E::G2Affine> {
        match self.key {
            ValidatorPublicKey::Announced(key) => Ok(key.encryption_key),
            ValidatorPublicKey::Unannounced => Err(anyhow!(
                "The encryption key for this validator was not announced"
            )),
        }
    }
}

/// Initially we do not know the ephemeral public keys
/// of participating validators. We only learn these
/// as they are announced.
#[derive(Clone, Debug)]
pub enum ValidatorPublicKey<E: PairingEngine> {
    Announced(PublicKey<E>),
    Unannounced,
}

impl<E: PairingEngine> CanonicalSerialize for ValidatorPublicKey<E> {
    #[inline]
    fn serialize<W: Write>(
        &self,
        mut writer: W,
    ) -> Result<(), SerializationError> {
        match self {
            Self::Announced(key) => Some(*key),
            Self::Unannounced => None,
        }
        .serialize(&mut writer)
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        match self {
            Self::Announced(key) => Some(*key),
            Self::Unannounced => None,
        }
        .serialized_size()
    }
}

impl<E: PairingEngine> CanonicalDeserialize for ValidatorPublicKey<E> {
    #[inline]
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let is_some = bool::deserialize(&mut reader)?;
        let data = if is_some {
            Self::Announced(PublicKey::<E>::deserialize(&mut reader)?)
        } else {
            Self::Unannounced
        };
        Ok(data)
    }
}

impl Rng for ark_std::rand::prelude::StdRng {}

pub trait Rng: ark_std::rand::CryptoRng + ark_std::rand::RngCore {}

pub mod ark_serde {
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use serde_bytes::{Deserialize, Serialize};

    /// Serialize an ark type with serde
    pub fn serialize<S, T>(data: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        T: CanonicalSerialize + std::fmt::Debug,
    {
        use serde::ser::Error;
        let mut bytes = vec![];
        data.serialize(&mut bytes).map_err(S::Error::custom)?;
        serde_bytes::Bytes::new(&bytes).serialize(serializer)
    }
    /// Deserialize an ark type with serde
    pub fn deserialize<'d, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'d>,
        T: CanonicalDeserialize,
    {
        use serde::de::Error;
        let bytes = <serde_bytes::ByteBuf>::deserialize(deserializer)?;
        T::deserialize(bytes.as_slice()).map_err(D::Error::custom)
    }
}

#[test]
fn test_ark_serde() {
    use ark_bls12_381::G1Affine;
    use serde::{Deserialize, Serialize};
    #[derive(Serialize, Deserialize)]
    struct Test {
        #[serde(with = "ark_serde")]
        pub p: G1Affine,
    }
    use ark_ec::AffineCurve;
    let p = G1Affine::prime_subgroup_generator();
    let t = Test { p };
    let m = serde_json::to_string(&t).unwrap();
    let _t2: Test = serde_json::from_str(&m).unwrap();
    let m = bincode::serialize(&t).unwrap();
    let _t2: Test = bincode::deserialize(&m).unwrap();
}
