/*
BLS threshold signatures.
*/

use crate::hash_to_field::{hash_to_field, ExpandMsgXmd};
use bls12_381::{G1Affine, G1Projective, Scalar};

fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Scalar {
    hash_to_field::<Scalar, ExpandMsgXmd<sha2::Sha256>>(msg, dst, 1)[0]
}

fn dst() -> Vec<u8> {
    b"dst".to_vec()
}

// coefficients for a set of public keys
fn coeffs(pubkeys: &[G1Affine]) -> Vec<Scalar> {
    // compressed public keys
    let cpks: Vec<[u8; 48]> =
        pubkeys.iter().map(G1Affine::to_compressed).collect();

    cpks.iter()
        .cloned()
        .map(|cpk| {
            let mut bs = cpk.to_vec();
            for cpk in &cpks {
                for b in cpk.iter() {
                    bs.push(*b)
                }
            }
            hash_to_scalar(&bs, &dst())
        })
        .collect()
}

// compute an aggregate public key
fn apk(pks: &[G1Affine]) -> G1Affine {
    pks.iter()
        .zip(coeffs(&pks))
        .map(|(pk, coeff)| pk * coeff)
        .sum::<G1Projective>()
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h2s() {
        ()
    }
}
