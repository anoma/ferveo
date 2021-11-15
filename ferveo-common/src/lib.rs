use ark_ec::PairingEngine;

pub mod keypair;
pub use keypair::*;

#[derive(Clone, Debug)]
pub struct Validator<E: PairingEngine> {
    pub key: PublicKey<E>,
    pub weight: u32,
    pub share_start: usize,
    pub share_end: usize,
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
    use serde::{Serialize, Deserialize};
    use ark_bls12_381::G1Affine;
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
