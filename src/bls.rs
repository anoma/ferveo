/*
BLS threshold signatures.
*/

use crate::hash_to_field::{hash_to_field, ExpandMsgXmd};
use bls12_381::{
    pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar,
};

fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Scalar {
    hash_to_field::<Scalar, ExpandMsgXmd<sha2::Sha256>>(msg, dst, 1)[0]
}

fn dst() -> Vec<u8> {
    // FIXME: change this out
    b"dst".to_vec()
}

fn hash_to_g2(msg: &[u8]) -> G2Affine {
    crate::hash_to_curve::htp_bls12381_g2(msg)
}

// extension methods for iterators
trait IterExt<A> {
    fn sum_by<B: std::iter::Sum<B>, F: Fn(A) -> B>(self, f: F) -> B;
}

impl<A, Iter: std::iter::Iterator<Item = A>> IterExt<A> for Iter {
    fn sum_by<B: std::iter::Sum<B>, F: Fn(A) -> B>(self, f: F) -> B {
        self.map(f).sum::<B>()
    }
}

// generate a public key from a secret scalar
pub fn pubkey(secret: &Scalar) -> G1Affine {
    (G1Projective::generator() * secret).into()
}

fn compressed_bytevec(g1: &G1Affine) -> Vec<u8> {
    g1.to_compressed().to_vec()
}

// sign a message with signature in G2
pub fn sign_g2(secret: Scalar, msg: &[u8]) -> G2Affine {
    (hash_to_g2(msg) * secret).into()
}

// sign a message with membership key and signature in G2
pub fn sign_with_mk_g2(secret: Scalar, mk: G2Affine, msg: &[u8]) -> G2Affine {
    (sign_g2(secret, msg) + G2Projective::from(mk)).into()
}

// verify a signature in G2 against a public key in G1
fn verify_g2(pk: &G1Affine, sig: &G2Affine, msg: &[u8]) -> bool {
    let lhs = pairing(pk, &hash_to_g2(msg));
    let rhs = pairing(&G1Affine::generator(), sig);
    lhs == rhs
}

#[derive(Eq, PartialEq)]
pub struct Keypair {
    pub secret: Scalar,
    pub pubkey: G1Affine,
}

impl PartialOrd for Keypair {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(
            self.pubkey
                .to_compressed()
                .cmp(&other.pubkey.to_compressed()),
        )
    }
}

impl Ord for Keypair {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl From<Scalar> for Keypair {
    fn from(secret: Scalar) -> Self {
        Keypair {
            secret,
            pubkey: pubkey(&secret),
        }
    }
}

// The setup information for a threshold bls scheme
pub struct Setup {
    pubkeys: Vec<G1Affine>,
    // The coefficients for each public key
    coeffs: Vec<Scalar>,
    // The aggregate public key for all participants
    apk: G1Affine,
}

impl std::iter::FromIterator<G1Affine> for Setup {
    fn from_iter<I: IntoIterator<Item = G1Affine>>(iter: I) -> Self {
        let mut pubkeys = Vec::from_iter(iter);
        // sort pubkeys by their compressed bytes
        pubkeys.sort_by_key(compressed_bytevec);
        // deduplicate
        pubkeys.dedup();

        // concatenation of all compressed pubkey bytes
        let concat_cpks: Vec<u8> =
            pubkeys.iter().flat_map(compressed_bytevec).collect();

        // compute the coefficient for a given public key
        let coeff = |pk: &G1Affine| -> Scalar {
            let msg = [&pk.to_compressed()[..], &concat_cpks[..]].concat();
            hash_to_scalar(&msg, &dst())
        };

        let coeffs: Vec<Scalar> = pubkeys.iter().map(coeff).collect();

        let apk = pubkeys.iter().zip(&coeffs).sum_by(|(pk, c)| pk * c).into();

        Setup {
            pubkeys,
            coeffs,
            apk,
        }
    }
}

impl Setup {
    // the number of participant keys in the setup
    pub fn members(&self) -> usize {
        self.pubkeys.len()
    }

    pub fn pubkeys(&self) -> &Vec<G1Affine> {
        &self.pubkeys
    }

    // The position of a public key in the setup
    pub fn pos(&self, pk: &G1Affine) -> Result<usize, usize> {
        let cpk_bytes = compressed_bytevec(&pk);
        self.pubkeys
            .binary_search_by_key(&cpk_bytes, compressed_bytevec)
    }

    pub fn coeffs(&self) -> &Vec<Scalar> {
        &self.coeffs
    }

    // The coefficient for a public key in the setup
    pub fn coeff(&self, pk: &G1Affine) -> Result<Scalar, usize> {
        self.pos(pk).map(|pos| self.coeffs[pos])
    }

    pub fn apk(&self) -> &G1Affine {
        &self.apk
    }

    // prefix a message with the compressed apk bytes
    pub fn prefix_apk(&self, msg: &[u8]) -> Vec<u8> {
        // compressed apk bytes
        let capk_bytes = self.apk().to_compressed();
        [&capk_bytes[..], &msg[..]].concat()
    }

    // The message to be signed for the `i`th member's membership key fragments
    fn memkey_frag_msg(&self, i: usize) -> Vec<u8> {
        self.prefix_apk(&(i as u64).to_le_bytes())
    }

    // The messages to be signed for each member's membership key fragments
    fn memkey_frag_msgs(&self) -> Vec<Vec<u8>> {
        (0..self.members())
            .map(|i| self.memkey_frag_msg(i))
            .collect()
    }

    // Generate the membership key fragments for each member from a keypair
    pub fn memkey_frags(&self, keys: &Keypair) -> Vec<G2Affine> {
        let coeff = self
            .coeff(&keys.pubkey)
            .expect("Public key not found in setup");
        // sign with secret * coeff
        let sign = |msg: &Vec<u8>| sign_g2(keys.secret * coeff, &msg);
        self.memkey_frag_msgs().iter().map(sign).collect()
    }

    // verify the `i`th membership key
    fn verify_memkey(&self, i: usize, mk: &G2Affine) -> bool {
        verify_g2(self.apk(), &mk, &self.memkey_frag_msg(i))
    }

    // Attempt to construct the `i`th membership key from its fragments
    pub fn memkey(&self, i: usize, frags: &[G2Affine]) -> Option<G2Affine> {
        let mk = frags.iter().sum_by(G2Projective::from).into();

        if self.verify_memkey(i, &mk) {
            Some(mk)
        } else {
            None
        }
    }

    /* verify a threshold signature,
    constructed from participants with the given positions in the setup */
    pub fn verify_threshold(
        &self,
        threshold: usize,
        sig: &G2Affine,
        positions: &[usize],
        msg: &[u8],
    ) -> bool {
        // sort and deduplicate positions
        let mut positions = positions.to_vec();
        positions.sort();
        positions.dedup();
        if positions.len() < threshold {
            false
        } else {
            let apk = &self.apk;
            let pubkeys = &self.pubkeys;
            // compute the aggregated participant pubkey
            let ppks = positions.iter().map(|i| pubkeys[*i]);
            let appk = ppks.sum_by(G1Projective::from).into();
            // the hash of the message prefixed by the compressed apk
            let msg_hash = hash_to_g2(&self.prefix_apk(msg));
            // the sum of the hashes of memkey fragment messages
            let mf_hash_sum: G2Affine = positions
                .into_iter()
                .sum_by(|i: usize| -> G2Projective {
                    hash_to_g2(&self.memkey_frag_msg(i)).into()
                })
                .into();
            let lhs = pairing(&G1Affine::generator(), sig);
            let rhs = pairing(&appk, &msg_hash) + pairing(apk, &mf_hash_sum);
            lhs == rhs
        }
    }
}
