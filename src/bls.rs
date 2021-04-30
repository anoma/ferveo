/*
BLS threshold signatures.
 */

//use crate::hash_to_field::{hash_to_field, ExpandMsgXmd};
use bls12_381::{
    multi_miller_loop,
    G1Affine,
    G1Projective,
    G2Affine, //G2Prepared,
    G2Projective,
    Gt,
    Scalar,
};

use rand::Rng;

pub fn random_scalar<R: Rng>(rng: &mut R) -> Scalar {
    let mut buf = [0; 64];
    rng.fill_bytes(&mut buf);
    Scalar::from_bytes_wide(&buf)
}

pub fn hash_to_g2(msg: &[u8]) -> G2Affine {
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

pub fn validate_pubkey(point: &G1Affine) -> bool {
    *point != G1Affine::identity() && bool::from(point.is_torsion_free())
}

fn compressed_bytevec(g1: &G1Affine) -> Vec<u8> {
    g1.to_compressed().to_vec()
}

// sign a message with signature in G2
pub fn sign_g2(secret: Scalar, msg: &[u8]) -> G2Affine {
    (hash_to_g2(msg) * secret).into()
}

// verify a signature in G2 against a public key in G1
pub fn verify_g2(pk: &G1Affine, sig: &G2Affine, msg: &[u8]) -> bool {
    if !validate_pubkey(pk) {
        false
    } else {
        let ml = multi_miller_loop(&[
            (pk, &hash_to_g2(msg).into()),
            (&-G1Affine::generator(), &(*sig).into()),
        ]);
        *pk != G1Affine::identity()
            && *sig != G2Affine::identity()
            && Gt::identity() == ml.final_exponentiation()
    }
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
    // Public keys of the participants
    pub pubkeys: Vec<G1Affine>,
    // Group public key
    pub group_pubkey: G1Affine,
}

impl Setup {
    // the number of participant keys in the setup
    pub fn members(&self) -> usize {
        self.pubkeys.len()
    }

    pub fn pubkeys(&self) -> &Vec<G1Affine> {
        &self.pubkeys
    }

    pub fn pubkey(&self) -> &G1Affine {
        &self.group_pubkey
    }

    // The position of a public key in the setup
    pub fn pos(&self, pk: &G1Affine) -> Result<usize, usize> {
        let cpk_bytes = compressed_bytevec(&pk);
        self.pubkeys
            .binary_search_by_key(&cpk_bytes, compressed_bytevec)
    }

    pub fn verify_partial_sigs(
        &self,
        partial_sigs: &[G2Affine],
        positions: &[usize],
        msg: &[u8],
    ) -> bool {
        for pk in positions.iter().map(|i| self.pubkeys[*i]).into_iter() {
            if !validate_pubkey(&pk) {
                return false;
            }
        }
        let mut sigma = G2Projective::identity();
        let mut pk = G1Projective::identity();
        for (sig, pubkey) in partial_sigs
            .iter()
            .zip(positions.iter().map(|i| self.pubkeys[*i]).into_iter())
        {
            sigma = sigma + sig;
            pk = pk + pubkey;
        }
        verify_g2(&pk.into(), &sigma.into(), msg)
    }

    pub fn build_group_signature(
        &self,
        partial_sigs: &[G2Affine],
        positions: &[usize],
    ) -> G2Affine {
        // Compute the lagrange coefficients in O(t²) using a naive algorithm
        let mut tmp = Scalar::one();
        let mut inv = Scalar::one();
        let lagrange_0: Vec<Scalar> = positions
            .iter()
            .map(|j| {
                tmp = Scalar::one();
                for k in positions.iter() {
                    if *k != *j {
                        tmp = tmp * Scalar::from(*k as u32);
                        inv = Scalar::invert(
                            &(Scalar::from(*k as u32)
                                - Scalar::from(*j as u32)),
                        )
                        .unwrap();
                        tmp = tmp * inv;
                    }
                }
                tmp
            })
            .collect();
        // Compute the signature from the partial signatures `partial_sigs`
        let mut sig = G2Projective::identity();
        for (j, sigma) in (*partial_sigs).iter().enumerate() {
            sig = sig + (sigma * lagrange_0[j]);
        }
        sig.into()
    }

    pub fn verify_multi_signatures(
        &self,
        sigs: &[G2Affine],
        msgs: &[&[u8]],
    ) -> bool {
        if !validate_pubkey(&self.group_pubkey) {
            false
        } else {
            let n = sigs.len();
            assert_eq!(n, msgs.len());
            let sig: G2Affine =
                sigs.into_iter().sum_by(G2Projective::from).into();
            let mut sum_hash_msgs = G2Projective::identity();
            for msg in msgs.iter() {
                sum_hash_msgs = sum_hash_msgs + hash_to_g2(msg);
            }
            let sum_hash_msgs_aff: G2Affine = sum_hash_msgs.into();
            let ml = multi_miller_loop(&[
                (&self.group_pubkey, &sum_hash_msgs_aff.into()),
                (&-G1Affine::generator(), &sig.into()),
            ]);
            Gt::identity() == ml.final_exponentiation()
        }
    }
}

pub fn eval(poly: &[Scalar], x: Scalar) -> Scalar {
    let mut res = Scalar::zero();
    for coeff in poly.iter().rev() {
        res = res * x + coeff;
    }
    res
}

#[test]
pub fn test_bls() {
    use rand::{seq::IteratorRandom, thread_rng, SeedableRng};

    let n = 10;
    let t = 8;

    // Fixed seed for reproducability
    fn rng() -> rand::rngs::StdRng {
        rand::rngs::StdRng::seed_from_u64(0)
    }
    let mut rng = rng();

    let mut rng_scalar = thread_rng();
    let poly: Vec<Scalar> =
        (0..t).map(|_| random_scalar(&mut rng_scalar)).collect();
    let group_secret = eval(&poly, Scalar::zero());
    let group_pk = pubkey(&group_secret);

    let secret_shares: Vec<Scalar> = (0..n)
        .map(|i| eval(&poly, Scalar::from(i as u32)))
        .collect();
    let pks: Vec<G1Affine> = secret_shares.iter().map(|s| pubkey(&s)).collect();

    let setup = Setup {
        pubkeys: pks.clone(),
        group_pubkey: group_pk.clone(),
    };

    let msg = b"lorem ipsum";
    let mut positions = (0..n).choose_multiple(&mut rng, t);
    positions.sort();

    let sigs: Vec<G2Affine> = positions
        .iter()
        .map(|i| sign_g2(secret_shares[*i], msg))
        .collect();
    assert!(setup.verify_partial_sigs(&sigs, &positions, msg));

    let sig = setup.build_group_signature(&sigs, &positions);
    assert!(verify_g2(&group_pk, &sig, msg));
}
