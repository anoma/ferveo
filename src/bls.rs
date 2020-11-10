/*
BLS threshold signatures.
*/

use crate::hash_to_field::{hash_to_field, ExpandMsgXmd};
use bls12_381::{G1Affine, G1Projective, G2Affine, Scalar};

fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Scalar {
    hash_to_field::<Scalar, ExpandMsgXmd<sha2::Sha256>>(msg, dst, 1)[0]
}

fn dst() -> Vec<u8> {
    b"dst".to_vec()
}

// generate the i'th coefficient for a slice of compressed public keys
fn coeff(cpks: &[[u8; 48]], i: usize) -> Scalar {
    let cpk_bytes = cpks[i].to_vec().into_iter();
    let cpks_bytes = cpks.iter().flat_map(|cpk| cpk.to_vec());
    let msg: Vec<u8> = cpk_bytes.chain(cpks_bytes).collect();
    hash_to_scalar(&msg, &dst())
}

// coefficients for a slice of compressed public keys
fn coeffs(cpks: &[[u8; 48]]) -> Vec<Scalar> {
    (0..cpks.len()).map(|i| coeff(&cpks, i)).collect()
}

// compute an aggregate public key
fn apk(pubkeys: &[G1Affine]) -> G1Affine {
    let cpks: Vec<[u8; 48]> =
        pubkeys.iter().map(G1Affine::to_compressed).collect();

    pubkeys
        .iter()
        .zip(coeffs(&cpks))
        .map(|(pubkey, coeff)| pubkey * coeff)
        .sum::<G1Projective>()
        .into()
}

// sign a message with signature in g1
fn sign_g1(secret: Scalar, msg: &[u8]) -> G1Affine {
    (crate::hash_to_curve::htp_bls12381_g1(msg) * secret).into()
}

// sign a message with signature in g2
fn sign_g2(secret: Scalar, msg: &[u8]) -> G2Affine {
    (crate::hash_to_curve::htp_bls12381_g2(msg) * secret).into()
}

// generate the membership key components for a given secret key
fn membership_key_components(
    secret: Scalar,
    pubkeys: &[G1Affine],
) -> Vec<G2Affine> {
    let pubkey = G1Affine::from(G1Projective::generator() * secret);
    let pos = pubkeys.iter().position(|pk| *pk == pubkey).unwrap();
    let cpks: Vec<[u8; 48]> =
        pubkeys.iter().map(G1Affine::to_compressed).collect();
    let coeff = coeff(&cpks, pos);
    // sign with secret * coeff
    let signing_secret = secret * coeff;
    // compressed apk bytes
    let capk_bytes = apk(pubkeys).to_compressed();
    (0..pubkeys.len() as u64)
        .map(|i| {
            let i_bytes = i.to_le_bytes();
            let msg = [&capk_bytes[..], &i_bytes[..]].concat();
            sign_g2(signing_secret, &msg)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h2s() {
        ()
    }
}
