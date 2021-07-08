#![allow(unused_imports)]
#![allow(non_camel_case_types)]
use crate::*;
use ark_serialize::*;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake2b_simd::{Params, State};
use rand::{CryptoRng, RngCore};
use std::convert::TryInto;

use ark_ec::{AffineCurve, PairingEngine};
use ark_ff::FromBytes;

//use crate::{Affine, Scalar};
use anyhow::{anyhow, Result};
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar as Scalar25519;
use serde::{Deserialize, Serialize};

#[derive(serde::Serialize, serde::Deserialize)]
pub struct NIZKP_25519 {
    pub c: [u8; 32],
    pub r: curve25519_dalek::scalar::Scalar,
}

pub struct XEdDSA {
    pub R: curve25519_dalek::edwards::CompressedEdwardsY,
    pub s: EdwardsPoint,
}

impl XEdDSA {
    pub fn new<R: Rng>(k: &Scalar25519, B: &MontgomeryPoint) -> Self {
        let (A, a) = Self::calculate_key_pair(k, B).unwrap();
        unimplemented!();
    }
    pub fn calculate_key_pair(
        k: &Scalar25519,
        B: &MontgomeryPoint,
    ) -> Result<(EdwardsPoint, Scalar25519)> {
        use subtle::ConditionallyNegatable;
        //let B = B.to_edwards(0).ok_or_else(anyhow!("bad montgomery base"))?;
        let E = k * B;
        //let A = E.to_edwards(0).ok_or_else(anyhow!("bad montgomery base"))?
        let mut a = k;
        //a.conditional_negate(E.X.is_negative());
        //E.0[31] &= !(1 << 7); // set sign bit to 0
        //Ok((E, a))
        unimplemented!()
    }
}

//TODO: use hash-to-field for both?

impl NIZKP_25519 {
    pub fn dleq<R: Rng>(
        x_1: &curve25519_dalek::montgomery::MontgomeryPoint,
        y_1: &curve25519_dalek::montgomery::MontgomeryPoint,
        x_2: &curve25519_dalek::montgomery::MontgomeryPoint,
        y_2: &curve25519_dalek::montgomery::MontgomeryPoint,
        alpha: &curve25519_dalek::scalar::Scalar,
        rng: &mut R,
    ) -> Self {
        let w = curve25519_dalek::scalar::Scalar::random(rng);
        let t_1 = x_1 * w;
        let t_2 = x_2 * w;
        let mut params = blake2b_simd::Params::new();
        params.hash_length(32);
        let mut hasher = params.to_state();

        hasher.update(x_1.as_bytes());
        hasher.update(y_1.as_bytes());
        hasher.update(x_2.as_bytes());
        hasher.update(y_2.as_bytes());
        hasher.update(t_1.as_bytes());
        hasher.update(t_2.as_bytes());

        let mut c = [0u8; 32];
        c.copy_from_slice(hasher.finalize().as_bytes());

        let r = w - alpha
            * curve25519_dalek::scalar::Scalar::from_bytes_mod_order(c);

        Self { c, r }
    }

    pub fn dleq_verify(
        &self,
        x_1: &curve25519_dalek::montgomery::MontgomeryPoint,
        y_1: &curve25519_dalek::montgomery::MontgomeryPoint,
        x_2: &curve25519_dalek::montgomery::MontgomeryPoint,
        y_2: &curve25519_dalek::montgomery::MontgomeryPoint,
    ) -> bool {
        let pi_c =
            curve25519_dalek::scalar::Scalar::from_bytes_mod_order(self.c);

        let x_1_edwards_r = x_1.to_edwards(0).unwrap() * self.r;
        let x_2_edwards_r = x_2.to_edwards(0).unwrap() * self.r;
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
            c == self.c
        };
        try_sign(0, 0) ^ try_sign(0, 1) ^ try_sign(1, 0) ^ try_sign(1, 1)
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct NIZKP<A: ark_ec::AffineCurve> {
    #[serde(with = "crate::ark_serde")]
    pub c: A::ScalarField,
    #[serde(with = "crate::ark_serde")]
    pub r: A::ScalarField,
}
impl<Affine> NIZKP<Affine>
where
    Affine: ark_ec::AffineCurve,
{
    pub fn dleq<R: Rng>(
        x_1: &Affine,
        y_1: &Affine,
        x_2: &Affine,
        y_2: &Affine,
        alpha: &Affine::ScalarField,
        rng: &mut R,
    ) -> Self {
        use ark_ff::ToBytes;
        use ark_std::UniformRand;
        use blake2b_simd::State;

        let w = Affine::ScalarField::rand(rng);
        let t_1 = Affine::from(x_1.mul(w));
        let t_2 = Affine::from(x_2.mul(w));
        let mut params = blake2b_simd::Params::new();
        params.hash_length(32);
        let mut hasher = params.to_state();

        let c: Affine::ScalarField; //TODO: use hash to field?
        loop {
            let mut buf = Vec::new();
            x_1.write(&mut buf).unwrap();
            y_1.write(&mut buf).unwrap();
            x_2.write(&mut buf).unwrap();
            y_2.write(&mut buf).unwrap();
            t_1.write(&mut buf).unwrap();
            t_2.write(&mut buf).unwrap();
            hasher.update(buf.as_slice());
            if let Ok(h) =
                Affine::ScalarField::read(hasher.finalize().as_bytes())
            {
                c = h;
                break;
            }
        }

        let r = w - *alpha * c;

        Self { c, r }
    }

    pub fn dleq_verify(
        &self,
        x_1: &Affine,
        y_1: &Affine,
        x_2: &Affine,
        y_2: &Affine,
    ) -> bool {
        use ark_ff::FromBytes;
        use ark_ff::ToBytes;
        use blake2b_simd::State;

        let t_1 = Affine::from(x_1.mul(self.r) + y_1.mul(self.c));
        let t_2 = Affine::from(x_2.mul(self.r) + y_2.mul(self.c));

        let mut params = blake2b_simd::Params::new();
        params.hash_length(32);
        let mut hasher = params.to_state();
        let c: Affine::ScalarField;
        loop {
            let mut buf = Vec::new();
            x_1.write(&mut buf);
            y_1.write(&mut buf);
            x_2.write(&mut buf);
            y_2.write(&mut buf);
            t_1.write(&mut buf);
            t_2.write(&mut buf);
            hasher.update(buf.as_slice());
            if let Ok(h) =
                Affine::ScalarField::read(hasher.finalize().as_bytes())
            {
                c = h;
                break;
            }
        }
        c == self.c
    }
}
#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct SchnorrPoK<E: PairingEngine> {
    #[serde(with = "crate::ark_serde")]
    pub s: E::Fr,
    #[serde(with = "crate::ark_serde")]
    pub e: E::Fr,
}

impl<E: PairingEngine> SchnorrPoK<E> {
    pub fn new<R: Rng>(
        g: E::G1Affine,
        x: E::Fr,
        g_x: E::G1Affine,
        rng: &mut R,
    ) -> Self {
        use ark_ff::ToBytes;
        use ark_std::UniformRand;
        use blake2b_simd::State;
        let k = E::Fr::rand(rng);
        let r = g.mul(k);

        let mut params = blake2b_simd::Params::new();
        params.hash_length(32);
        let mut hasher = params.to_state();

        let e =  //TODO: use hash to field?
        loop {
            let mut buf = Vec::new();
            r.write(&mut buf).unwrap();
            g.write(&mut buf).unwrap();
            g_x.write(&mut buf).unwrap();

            hasher.update(buf.as_slice());
            if let Ok(h) = E::Fr::read(hasher.finalize().as_bytes()) {
                break h;
            }
        };
        let s = k - x * e;
        Self { s, e }
    }
    pub fn verify(&self, g: E::G1Affine, g_x: E::G1Affine) -> bool {
        use ark_ff::ToBytes;
        use blake2b_simd::State;

        let mut params = blake2b_simd::Params::new();
        params.hash_length(32);
        let mut hasher = params.to_state();

        let r = g.mul(self.s);
        let e = loop {
            let mut buf = Vec::new();
            r.write(&mut buf).unwrap();
            g.write(&mut buf).unwrap();
            g_x.write(&mut buf).unwrap();

            hasher.update(buf.as_slice());
            if let Ok(h) = E::Fr::read(hasher.finalize().as_bytes()) {
                break h;
            }
        };
        e == self.e
    }
}

#[test]
fn test_nizkp() {
    use curve25519_dalek::montgomery::MontgomeryPoint;
    use curve25519_dalek::scalar::Scalar;
    let mut rng = ark_std::test_rng();
    use x25519_dalek::{PublicKey, StaticSecret};

    for _ in 0..1000 {
        let alice_secret = StaticSecret::new(&mut rng);
        let alice_public = PublicKey::from(&alice_secret);
        let bob_secret = StaticSecret::new(&mut rng);
        let bob_public = PublicKey::from(&bob_secret);
        let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);

        let pi = NIZKP_25519::dleq(
            &curve25519_dalek::constants::X25519_BASEPOINT,
            &MontgomeryPoint(alice_public.to_bytes()),
            &MontgomeryPoint(bob_public.to_bytes()),
            &MontgomeryPoint(alice_shared_secret.to_bytes()),
            &Scalar::from_bytes_mod_order(alice_secret.to_bytes()),
            &mut rng,
        );
        assert!(pi.dleq_verify(
            &curve25519_dalek::constants::X25519_BASEPOINT,
            &MontgomeryPoint(alice_public.to_bytes()),
            &MontgomeryPoint(bob_public.to_bytes()),
            &MontgomeryPoint(alice_shared_secret.to_bytes()),
        ));
    }
}

#[test]
fn test_nizkp_pallas() {
    type Affine = ark_pallas::Affine;
    type Scalar = ark_pallas::Fr;
    let mut rng = ark_std::test_rng();
    use ark_ec::ProjectiveCurve;
    use ark_std::UniformRand;
    for _ in 0..1000 {
        let secret = Scalar::rand(&mut rng);
        let g_base = Affine::prime_subgroup_generator();
        let g = g_base.mul(secret);
        let h_base = g_base + g_base;
        let h = h_base.mul(secret);

        let pi = NIZKP::<Affine>::dleq(
            &g_base,
            &g.into(),
            &h_base,
            &h.into(),
            &secret,
            &mut rng,
        );
        assert!(pi.dleq_verify(&g_base, &g.into(), &h_base, &h.into()));
    }
}
