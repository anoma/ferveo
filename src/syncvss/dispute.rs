use crate::dkg;
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize};
use rand::{CryptoRng, RngCore};
use ark_serialize::*;

//#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct NIZKP {
    pub c : [u8; 32],
    pub r : curve25519_dalek::scalar::Scalar,
}

//#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Dispute {
    pub hash : [u8; 32],
    pub shared_secret: x25519_dalek::SharedSecret,
    pub nizkp : NIZKP, 
}

pub fn dleq<R: rand::Rng + rand::RngCore + rand::CryptoRng>(x_1 : &curve25519_dalek::montgomery::MontgomeryPoint,
    y_1 : &curve25519_dalek::montgomery::MontgomeryPoint,
    x_2 : &curve25519_dalek::montgomery::MontgomeryPoint,
    y_2 : &curve25519_dalek::montgomery::MontgomeryPoint,
    alpha : &curve25519_dalek::scalar::Scalar,
    rng: &mut R)
    -> NIZKP
    {
        use std::convert::TryInto;
        use blake2::{Blake2b, Digest};
        let w = curve25519_dalek::scalar::Scalar::random(rng);
        let t_1 = x_1 * w;
        let t_2 = x_2 * w;
        let mut hasher = Blake2b::new();
        hasher.update(x_1.as_bytes());
        hasher.update(y_1.as_bytes());
        hasher.update(x_2.as_bytes());
        hasher.update(y_2.as_bytes());
        hasher.update(t_1.as_bytes());
        hasher.update(t_2.as_bytes());
        
        let c : [u8; 32] = hasher.finalize()[..].try_into().unwrap();

        let r = w - alpha*curve25519_dalek::scalar::Scalar::from_bytes_mod_order(c);

        NIZKP { c, r }
    }

pub fn send_dispute(dkg: &mut dkg::Context) {

}

pub fn recv_dispute(dkg: &mut dkg::Context, dispute: Vec<u8>) {
    
}