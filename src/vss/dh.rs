use crate::*;
use ark_ec::AffineCurve;
use ark_serialize::*;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use ark_ff::PrimeField;

use nizkp::NIZKP;

#[derive(CanonicalSerialize, CanonicalDeserialize, Debug)]
pub struct NodeSharesPlaintext<Affine>
where
    Affine: AffineCurve,
{
    pub shares: Vec<Affine::ScalarField>,
}

impl<Affine> NodeSharesPlaintext<Affine>
where
    Affine: AffineCurve,
{
    pub fn encrypt(
        &self,
        cipher: &chacha20poly1305::XChaCha20Poly1305,
    ) -> NodeSharesCiphertext {
        let mut msg = vec![];
        self.shares.serialize(&mut msg).unwrap();

        let nonce = [0u8; 24]; //TODO: add nonce?
        NodeSharesCiphertext(cipher.encrypt(&nonce.into(), &msg[..]).unwrap())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NodeSharesCiphertext(Vec<u8>);

impl NodeSharesCiphertext {
    pub fn decrypt<Affine: AffineCurve>(
        &self,
        cipher: &chacha20poly1305::XChaCha20Poly1305,
    ) -> Result<NodeSharesPlaintext<Affine>, anyhow::Error> {
        let nonce = [0u8; 24]; //TODO: add nonce?

        let dec_share = cipher.decrypt(&nonce.into(), &self.0[..]).unwrap(); //TODO: implement StdError for aead::error

        Ok(NodeSharesPlaintext::deserialize(&dec_share[..])?)
    }
}

#[test]
fn test_encrypt_decrypt() {
    let rng = &mut ark_std::test_rng();
    use ark_std::UniformRand;
    type Affine = ark_pallas::Affine;

    for _ in 0..1000 {
        let alice_secret = dh::AsymmetricKeypair::<Affine>::new(rng);

        let alice_public = alice_secret.public();
        let bob_secret = dh::AsymmetricKeypair::new(rng);

        let bob_public = bob_secret.public();

        let mut sent_shares = vec![];
        for _ in 0..1000 {
            sent_shares.push(<Affine as AffineCurve>::ScalarField::rand(rng));
        }

        let enc = NodeSharesPlaintext::<Affine> {
            shares: sent_shares,
        }
        .encrypt(&alice_secret.encrypt_cipher(&bob_public));

        //let domain = vec![Scalar::zero(); 1000]; //TODO: real domain

        let _dec = enc
            .decrypt::<Affine>(&bob_secret.decrypt_cipher(&alice_public))
            .unwrap();
    }
}
