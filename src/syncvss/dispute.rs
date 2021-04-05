use crate::dkg;
use ark_serialize::*;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
//use blake2::{Blake2b, Digest};
use blake2b_simd::{Params, State};
use rand::{CryptoRng, RngCore};
use std::convert::TryInto;

//#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct NIZKP {
    pub c: [u8; 32],
    pub r: curve25519_dalek::scalar::Scalar,
}

//#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Dispute {
    pub hash: [u8; 32],
    pub shared_secret: x25519_dalek::SharedSecret,
    pub nizkp: NIZKP,
}

pub fn dleq<R: rand::Rng + rand::RngCore + rand::CryptoRng>(
    x_1: &curve25519_dalek::montgomery::MontgomeryPoint,
    y_1: &curve25519_dalek::montgomery::MontgomeryPoint,
    x_2: &curve25519_dalek::montgomery::MontgomeryPoint,
    y_2: &curve25519_dalek::montgomery::MontgomeryPoint,
    alpha: &curve25519_dalek::scalar::Scalar,
    rng: &mut R,
) -> NIZKP {
    let w = curve25519_dalek::scalar::Scalar::random(rng);
    let t_1 = x_1 * w;
    let t_2 = x_2 * w;
    let mut params = blake2b_simd::Params::new();
    params.hash_length(32);
    let mut hasher = params.to_state();

    dbg!(t_1);
    dbg!(t_2);

    hasher.update(x_1.as_bytes());
    hasher.update(y_1.as_bytes());
    hasher.update(x_2.as_bytes());
    hasher.update(y_2.as_bytes());
    hasher.update(t_1.as_bytes());
    hasher.update(t_2.as_bytes());

    let mut c = [0u8; 32];
    c.copy_from_slice(hasher.finalize().as_bytes());

    let r =
        w - alpha * curve25519_dalek::scalar::Scalar::from_bytes_mod_order(c);

    NIZKP { c, r }
}

pub fn dleq_verify(
    x_1: &curve25519_dalek::montgomery::MontgomeryPoint,
    y_1: &curve25519_dalek::montgomery::MontgomeryPoint,
    x_2: &curve25519_dalek::montgomery::MontgomeryPoint,
    y_2: &curve25519_dalek::montgomery::MontgomeryPoint,
    pi: &NIZKP,
) -> bool {
    let pi_c = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(pi.c);

    let x_1_edwards_r = x_1.to_edwards(0).unwrap() * pi.r;
    let x_2_edwards_r = x_2.to_edwards(0).unwrap() * pi.r;
    let try_sign = |sign_1: u8, sign_2: u8| {
        let t_1 = x_1_edwards_r + (y_1.to_edwards(sign_1).unwrap() * pi_c);
        let t_2 = x_2_edwards_r + (y_2.to_edwards(sign_2).unwrap() * pi_c);

        let mut params = blake2b_simd::Params::new();
        params.hash_length(32);
        let mut hasher = params.to_state();
        hasher.update(x_1.as_bytes());
        hasher.update(y_1.as_bytes());
        hasher.update(x_2.as_bytes());
        hasher.update(y_2.as_bytes());
        hasher.update(t_1.to_montgomery().as_bytes());
        hasher.update(t_2.to_montgomery().as_bytes());

        let mut c = [0u8; 32];
        c.copy_from_slice(hasher.finalize().as_bytes());
        c == pi.c
    };
    try_sign(0, 0) ^ try_sign(0, 1) ^ try_sign(1, 0) ^ try_sign(1, 1)
}
pub fn send_dispute(dkg: &mut dkg::Context) {}

pub fn recv_dispute(dkg: &mut dkg::Context, dispute: Vec<u8>) {}

#[test]
fn test_nizkp() {
    use rand_chacha::rand_core::{RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;
    //use rand::RngCore;
    use curve25519_dalek::montgomery::MontgomeryPoint;
    use curve25519_dalek::scalar::Scalar;
    let mut rng = rand::thread_rng();
    //let mut rng = ChaCha8Rng::from_seed([0u8;32]);
    use x25519_dalek::{PublicKey, StaticSecret};

    for _ in (0..1000) {
        let alice_secret = StaticSecret::new(&mut rng);
        let alice_public = PublicKey::from(&alice_secret);
        let bob_secret = StaticSecret::new(&mut rng);
        let bob_public = PublicKey::from(&bob_secret);
        let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);

        let pi = dleq(
            &curve25519_dalek::constants::X25519_BASEPOINT,
            &MontgomeryPoint(alice_public.to_bytes()),
            &MontgomeryPoint(bob_public.to_bytes()),
            &MontgomeryPoint(alice_shared_secret.to_bytes()),
            &Scalar::from_bytes_mod_order(alice_secret.to_bytes()),
            &mut rng,
        );
        assert!(dleq_verify(
            &curve25519_dalek::constants::X25519_BASEPOINT,
            &MontgomeryPoint(alice_public.to_bytes()),
            &MontgomeryPoint(bob_public.to_bytes()),
            &MontgomeryPoint(alice_shared_secret.to_bytes()),
            &pi
        ));
    }
}
