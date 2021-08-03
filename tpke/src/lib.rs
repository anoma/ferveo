use crate::hash_to_curve::htp_bls12381_g2;
use crate::subproductdomain::SubproductDomain;
use ark_ec::{msm::FixedBaseMSM, AffineCurve, PairingEngine};
use ark_ff::{Field, One, PrimeField, ToBytes, UniformRand, Zero};
use ark_poly::EvaluationDomain;
use ark_poly::{univariate::DensePolynomial, Polynomial, UVPolynomial};
use ark_serialize::CanonicalSerialize;
use itertools::izip;

use rand_core::RngCore;
use rayon::prelude::*;
use std::usize;
use thiserror::Error;

mod ciphertext;
mod hash_to_curve;
mod subproductdomain;
pub use ciphertext::*;
mod key_share;
pub use key_share::*;
mod decryption;
pub use decryption::*;
mod combine;
pub use combine::*;
mod context;
pub use context::*;

pub trait ThresholdEncryptionParameters {
    type E: PairingEngine;
}
#[derive(Debug, Error)]
pub enum ThresholdEncryptionError {
    /// Error
    #[error("ciphertext verification failed")]
    CiphertextVerificationFailed,

    /// Error
    #[error("Decryption share verification failed")]
    DecryptionShareVerificationFailed,

    /// Hashing to curve failed
    #[error("Could not hash to curve")]
    HashToCurveError,

    #[error("plaintext verification failed")]
    PlaintextVerificationFailed,
}

fn hash_to_g2<T: ark_serialize::CanonicalDeserialize>(message: &[u8]) -> T {
    let mut point_ser: Vec<u8> = Vec::new();
    let point = htp_bls12381_g2(message);
    point.serialize(&mut point_ser).unwrap();
    T::deserialize(&point_ser[..]).unwrap()
}

fn construct_tag_hash<E: PairingEngine>(u: E::G1Affine, stream_ciphertext: &[u8]) -> E::G2Affine {
    let mut hash_input = Vec::<u8>::new();
    u.write(&mut hash_input).unwrap();
    hash_input.extend_from_slice(stream_ciphertext);

    hash_to_g2(&hash_input)
}

pub fn setup<E: PairingEngine>(
    threshold: usize,
    shares_num: usize,
    num_entities: usize,
) -> (E::G1Affine, E::G2Affine, Vec<PrivateDecryptionContext<E>>) {
    let rng = &mut ark_std::test_rng();
    let g = E::G1Affine::prime_subgroup_generator();
    let h = E::G2Affine::prime_subgroup_generator();
    let g_inv = E::G1Prepared::from(-g);
    let h_inv = E::G2Prepared::from(-h);

    assert!(shares_num >= threshold);
    let threshold_poly = DensePolynomial::<E::Fr>::rand(threshold - 1, rng);

    let fft_domain = ark_poly::Radix2EvaluationDomain::<E::Fr>::new(shares_num).unwrap();
    let evals = threshold_poly.evaluate_over_domain_by_ref(fft_domain);
    let mut domain_points = Vec::with_capacity(shares_num);
    let mut point = E::Fr::one();
    let mut domain_points_inv = Vec::with_capacity(shares_num);
    let mut point_inv = E::Fr::one();

    for _ in 0..shares_num {
        domain_points.push(point);
        point *= fft_domain.group_gen;
        domain_points_inv.push(point_inv);
        point_inv *= fft_domain.group_gen_inv;
    }

    let window_size = FixedBaseMSM::get_mul_window_size(100);
    let scalar_bits = E::Fr::size_in_bits();

    let pubkey_shares = subproductdomain::fast_multiexp(&evals.evals, g.into_projective());
    let privkey_shares = subproductdomain::fast_multiexp(&evals.evals, h.into_projective());

    let x = threshold_poly.coeffs[0];
    let pubkey = g.mul(x);
    let privkey = h.mul(x);

    let mut private_contexts = vec![];
    let mut public_contexts = vec![];

    for (index, (domain, domain_inv, public, private)) in izip!(
        domain_points.chunks(shares_num / num_entities),
        domain_points_inv.chunks(shares_num / num_entities),
        pubkey_shares.chunks(shares_num / num_entities),
        privkey_shares.chunks(shares_num / num_entities)
    )
    .enumerate()
    {
        let private_key_share = PrivateKeyShare::<E> {
            private_key_shares: private.to_vec(),
        };
        let b = E::Fr::rand(rng);
        let mut blinded_key_shares = private_key_share.blind(b.clone());
        blinded_key_shares.multiply_by_omega_inv(domain_inv);
        /*blinded_key_shares.window_tables =
        blinded_key_shares.get_window_table(window_size, scalar_bits, domain_inv);*/
        private_contexts.push(PrivateDecryptionContext::<E> {
            index,
            b,
            b_inv: b.inverse().unwrap(),
            private_key_share,
            public_decryption_contexts: vec![],
            g,
            g_inv: E::G1Prepared::from(-g),
            h_inv: E::G2Prepared::from(-h),
            scalar_bits,
            window_size,
        });
        let mut lagrange_N_0 = domain.iter().product::<E::Fr>();
        if domain.len() % 2 == 1 {
            lagrange_N_0 = -lagrange_N_0;
        }
        public_contexts.push(PublicDecryptionContext::<E> {
            domain: domain.to_vec(),
            public_key_shares: PublicKeyShares::<E> {
                public_key_shares: public.to_vec(),
            },
            blinded_key_shares,
            lagrange_N_0,
        });
    }
    for private in private_contexts.iter_mut() {
        private.public_decryption_contexts = public_contexts.clone();
    }

    (pubkey.into(), privkey.into(), private_contexts)
}

pub fn generate_random<R: RngCore, E: PairingEngine>(n: usize, rng: &mut R) -> Vec<E::Fr> {
    (0..n).map(|_| E::Fr::rand(rng)).collect::<Vec<_>>()
}

#[cfg(test)]
mod tests {
    use crate::*;
    use ark_std::test_rng;

    type E = ark_bls12_381::Bls12_381;

    #[test]
    fn symmetric_encryption() {
        let mut rng = test_rng();
        let threshold = 3;
        let shares_num = 5;
        let num_entities = 5;

        let msg: &[u8] = "abc".as_bytes();

        let (pubkey, privkey, _) = setup::<E>(threshold, shares_num, num_entities);

        let ciphertext = encrypt::<ark_std::rand::rngs::StdRng, E>(msg, pubkey, &mut rng);
        let plaintext = decrypt(&ciphertext, privkey);

        assert!(msg == plaintext)
    }

    #[test]
    fn threshold_encryption() {
        let rng = &mut test_rng();
        let threshold = 16 * 2 / 3;
        let shares_num = 16;
        let num_entities = 5;
        let msg: &[u8] = "abc".as_bytes();

        let (pubkey, privkey, contexts) = setup::<E>(threshold, shares_num, num_entities);
        let ciphertext = encrypt::<_, E>(msg, pubkey, rng);

        let mut shares: Vec<DecryptionShare<E>> = vec![];
        for context in contexts.iter() {
            shares.push(context.create_share(&ciphertext));
        }
        /*for pub_context in contexts[0].public_decryption_contexts.iter() {
            assert!(pub_context
                .blinded_key_shares
                .verify_blinding(&pub_context.public_key_shares, rng));
        }*/
        let prepared_blinded_key_shares = contexts[0].prepare_combine(&shares);
        let s = contexts[0].share_combine(&ciphertext, &shares, &prepared_blinded_key_shares);

        let plaintext = decrypt_with_shared_secret(&ciphertext, &s);
        assert!(plaintext == msg)
    }
}
