use anyhow::Result;
use ark_ec::PairingEngine;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write,
};

pub mod keypair;
pub use keypair::*;
use std::cmp::Ordering;

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
/// Represents a tendermint validator
pub struct TendermintValidator<E: PairingEngine> {
    /// Total voting power in tendermint consensus
    pub power: u64,
    /// The established address of the validator
    pub address: String,
    /// The Public key
    pub public_key: PublicKey<E>,
}

impl<E: PairingEngine> PartialEq for TendermintValidator<E> {
    fn eq(&self, other: &Self) -> bool {
        (self.power, &self.address) == (other.power, &other.address)
    }
}

impl<E: PairingEngine> Eq for TendermintValidator<E> {}

impl<E: PairingEngine> PartialOrd for TendermintValidator<E> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some((self.power, &self.address).cmp(&(other.power, &other.address)))
    }
}

impl<E: PairingEngine> Ord for TendermintValidator<E> {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.power, &self.address).cmp(&(other.power, &other.address))
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
/// The set of tendermint validators for a dkg instance
pub struct ValidatorSet<E: PairingEngine> {
    pub validators: Vec<TendermintValidator<E>>,
}

impl<E: PairingEngine> ValidatorSet<E> {
    /// Sorts the validators from highest to lowest. This ordering
    /// first considers staking weight and breaks ties on established
    /// address
    pub fn new(mut validators: Vec<TendermintValidator<E>>) -> Self {
        // reverse the ordering here
        validators.sort_by(|a, b| b.cmp(a));
        Self { validators }
    }

    /// Get the total voting power of the validator set
    pub fn total_voting_power(&self) -> u64 {
        self.validators.iter().map(|v| v.power).sum()
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Validator<E: PairingEngine> {
    pub validator: TendermintValidator<E>,
    pub weight: u32,
    pub share_start: usize,
    pub share_end: usize,
}

impl<E: PairingEngine> PartialEq for Validator<E> {
    fn eq(&self, other: &Self) -> bool {
        (
            &self.validator,
            self.weight,
            self.share_start,
            self.share_end,
        ) == (
            &other.validator,
            other.weight,
            other.share_start,
            other.share_end,
        )
    }
}

impl<E: PairingEngine> Eq for Validator<E> {}

impl<E: PairingEngine> PartialOrd for Validator<E> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.validator.cmp(&other.validator))
    }
}

impl<E: PairingEngine> Ord for Validator<E> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.validator.cmp(&other.validator)
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
