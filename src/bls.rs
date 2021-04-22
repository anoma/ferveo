/*
BLS threshold signatures.
 */

use crate::hash_to_field::{hash_to_field, ExpandMsgXmd};
use bls12_381::{
    multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared,
    G2Projective, Gt, Scalar,
};

use rand::{Rng, thread_rng, SeedableRng, seq::IteratorRandom};

// Fixed seed for reproducability
fn rng() -> rand::rngs::StdRng {
    rand::rngs::StdRng::seed_from_u64(0)
}

pub fn random_scalar<R: Rng>(rng: &mut R) -> Scalar {
    let mut buf = [0; 64];
    rng.fill_bytes(&mut buf);
    Scalar::from_bytes_wide(&buf)
}

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
    pub pubkeys: Vec<G1Affine>,
    // The coefficients for each public key
    pub coeffs: Vec<Scalar>,
    // The aggregate public key for all participants
    pub apk: G1Affine,
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

    /*
     * verify a signature `sig` from the participants of the group
     * defined in the setup.
     */
    pub fn verify_aggregated(&self, sig: &G2Affine, msg: &[u8]) -> bool {
        // key validation
        let mut foo: bool = true;
        for pk in self.pubkeys.iter() {
            foo = foo && validate_pubkey(&pk);
        }
        foo && verify_g2(&self.apk, sig, &self.prefix_apk(msg))
    }
}

pub fn verify_multi_aggregated_sig(
    setups: &[&Setup],
    sigs: &[G2Affine],
    msgs: &[&[u8]],
) -> bool {
    let n = setups.len();
    assert_eq!(n, sigs.len());
    assert_eq!(n, msgs.len());

    // key validation
    let mut foo: bool = true;
    for i in 0..n {
        for pk in setups[i].pubkeys.iter() {
            foo = foo && validate_pubkey(&pk);
        }
    }
    if !foo {
        false
    } else {
        let sig: G2Affine = sigs.into_iter().sum_by(G2Projective::from).into();
        let mut ml_g1 = vec![G1Affine::identity(); n + 1];
        let mut ml_g2 = vec![G2Affine::identity().into(); n + 1];
        ml_g1[0] = -G1Affine::generator();
        ml_g2[0] = sig.into();

        for i in 0..n {
            ml_g1[i + 1] = setups[i].apk;
            ml_g2[i + 1] = hash_to_g2(&setups[i].prefix_apk(msgs[i])).into();
        }

        Gt::identity()
            == multi_miller_loop(
                &ml_g1
                    .iter()
                    .zip(ml_g2.iter())
                    .collect::<Vec<(&G1Affine, &G2Prepared)>>(),
            )
            .final_exponentiation()
    }
}

pub fn dealer_gen_keys(n: usize) {
    
    // compute a secret s, secret shares s_i, and the public key
    // associated for verifying a (complete) sig
}

pub fn sign(
    partial_sigs: &[G2Affine],
    positions: &[usize]
) -> G2Affine {
    // Compute the lagrange coefficients in O(t²) using a naive algorithm
    let mut tmp = Scalar::one();
    let mut inv = Scalar::one();
    let lagrange_0 : Vec<Scalar> = positions.iter().map(|j| {
	tmp = Scalar::one();
	for k in positions.iter() {
	    if *k != *j {
		tmp = tmp * Scalar::from(*k as u32);
		inv = Scalar::invert(
		    &(Scalar::from(*k as u32) - Scalar::from(*j as u32))
		).unwrap();
		tmp = tmp * inv;
	    }
	}
	tmp
    }).collect();
    
    // Compute the signature from the partial signatures `partial_sigs`
    let mut sig = G2Projective::identity();
    for (j, sigma) in (*partial_sigs).iter().enumerate() {
    	sig = sig + (sigma * lagrange_0[j]);
    }
    sig.into()
}

pub fn eval(poly: &[Scalar], x: Scalar) -> Scalar {
    let mut res = Scalar::zero();
    for coeff in poly.iter().rev() {
	res = res * x + coeff;
    }
    res
}


#[test]
pub fn test1() {
    let n = 5;
    let t = 3;
    let mut rng = rng();
    let mut rng_scalar = thread_rng();
    let poly : Vec<Scalar> = (0..t)
	.map(|i| random_scalar(&mut rng_scalar)).collect();
    let secret = eval(&poly, Scalar::zero());
    let secret_shares : Vec<Scalar> = (0..n)
	.map(|i| eval(&poly, Scalar::from(i as u32))).collect();
    
    let msg = b"lorem ipsum";
    let mut positions = (0..n).choose_multiple(&mut rng, t);
    positions.sort();
    
    let mut sk = Scalar::zero();
    let mut sigs: Vec<G2Affine> = vec![G2Affine::identity(); t];
    for (cpt,i) in positions.iter().enumerate() {
	sk = secret_shares[*i];
	sigs[cpt] = sign_g2(sk, msg);
    }

    let sig = sign(&sigs, &positions);
    assert!(verify_g2(&(G1Affine::generator() * secret).into(), &sig,
		      msg));
}
