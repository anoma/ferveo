use ed25519_dalek as ed25519;
use ed25519_dalek::Signer;

use crate::*;
use serde::{Deserialize, Serialize};

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

impl SignedMessage {
    pub fn sign<M>(tau: u64, msg: &M, key: &ed25519::Keypair) -> SignedMessage
    where
        M: Serialize,
    {
        print_time!("Signing Message");
        let msg_bytes = bincode::serialize(&(tau, msg)).unwrap();
        let signature = key.sign(&msg_bytes);
        SignedMessage {
            msg_bytes,
            signature,
            signer: key.public,
        }
    }
    pub fn verify<'de, M>(&'de self) -> Result<(u64, M)>
    where
        M: Deserialize<'de>,
    {
        print_time!("Verifying Message");
        self.signer
            .verify_strict(&self.msg_bytes, &self.signature)?;
        bincode::deserialize::<'de, _>(&self.msg_bytes).map_err(|e| e.into()) //TODO: handle error
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SignedMessage {
    msg_bytes: Vec<u8>,
    signature: ed25519::Signature,
    pub signer: ed25519::PublicKey,
}

#[test]
fn test_ark_serde() {
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
