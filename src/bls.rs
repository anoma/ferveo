/*
BLS threshold signatures.
 */

use crate::hash_to_field::{hash_to_field, ExpandMsgXmd};
use bls12_381::{
    multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared,
    G2Projective, Gt, Scalar,
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
pub fn verify_g2(pk: &G1Affine, sig: &G2Affine, msg: &[u8]) -> bool {
    // TODO check subgroup and non-zero sig and pk ?
    let ml = multi_miller_loop(&[
        (pk, &hash_to_g2(msg).into()),
        (&-G1Affine::generator(), &(*sig).into()),
    ]);
    Gt::identity() == ml.final_exponentiation()
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

    pub fn prepare_threshold_verification(
        &self,
        threshold: usize,
        positions: &[usize],
        msg: &[u8],
        res_appk: &mut G1Affine,
        res_msg_hash: &mut G2Affine,
        res_apk: &mut G1Affine,
        res_mf_hash_sum: &mut G2Affine,
    ) -> bool {
        // sort and deduplicate positions
        let mut positions = positions.to_vec();
        positions.sort();
        positions.dedup();
        if positions.len() < threshold {
            false
        } else {
            *res_apk = self.apk;
            let pubkeys = &self.pubkeys;
            // compute the aggregated participant pubkey
            let ppks = positions.iter().map(|i| pubkeys[*i]);
            *res_appk = ppks.sum_by(G1Projective::from).into();
            // the hash of the message prefixed by the compressed apk
            *res_msg_hash = hash_to_g2(&self.prefix_apk(msg));

            // the sum of the hashes of memkey fragment messages
            *res_mf_hash_sum = positions
                .into_iter()
                .sum_by(|i: usize| -> G2Projective {
                    hash_to_g2(&self.memkey_frag_msg(i)).into()
                })
                .into();
            true
        }
    }

    /* verify a signature `sig` from `m` participants of the group
     * defined in the setup.
     */
    pub fn verify_aggregated(
        &self,
        sig: &G2Affine,
        msg: &[u8],
    ) -> bool {
    	verify_g2(&self.apk, sig, msg)
    }

    /* Verify a threshold signature constructed from participants with the
     * given positions in the setup
     * See the AMS of section 4.3 of the eprint 2018/483.
     */
    pub fn verify_threshold(
        &self,
        threshold: usize,
        sig: &G2Affine,
        positions: &[usize],
        msg: &[u8],
    ) -> bool {
        let mut appk = G1Affine::identity();
        let mut msg_hash = G2Affine::identity();
        let mut apk = G1Affine::identity();
        let mut mf_hash_sum = G2Affine::identity();
        let foo: bool = self.prepare_threshold_verification(
            threshold,
            positions,
            msg,
            &mut appk,
            &mut msg_hash,
            &mut apk,
            &mut mf_hash_sum,
        );
        let ml = multi_miller_loop(&[
            (&-G1Affine::generator(), &(*sig).into()),
            (&appk, &msg_hash.into()),
            (&apk, &mf_hash_sum.into()),
        ]);
        foo && Gt::identity() == ml.final_exponentiation()
    }
}

/*
 * Verify multiple aggregated signatures from different setups in 2*n+1
 * pairing computations instead of 3*n
 */
pub fn verify_multiple_sig(
    setups: &[&Setup],
    thresholds: &[usize],
    sigs: &[G2Affine],
    positions: &[&[usize]],
    msgs: &[&[u8]],
) -> bool {
    let n = (*setups).len();
    assert_eq!(n, thresholds.len());
    assert_eq!(n, sigs.len());
    assert_eq!(n, positions.len());
    assert_eq!(n, msgs.len());

    let sig: G2Affine = sigs.into_iter().sum_by(G2Projective::from).into();

    let mut ml_g1 = vec![G1Affine::identity(); 2 * n + 1];
    let mut ml_g2 = vec![G2Affine::identity().into(); 2 * n + 1];

    ml_g1[0] = -G1Affine::generator();
    ml_g2[0] = sig.into();

    let mut foo1: bool = true;

    for i in 0..n {
        // sort and deduplicate positions
        let mut positions = positions[i].to_vec();
        positions.sort();
        positions.dedup();
        if positions.len() < thresholds[i] {
            return false;
        } else {
            let mut appk = G1Affine::identity();
            let mut msg_hash = G2Affine::identity();
            let mut apk = G1Affine::identity();
            let mut mf_hash_sum = G2Affine::identity();
            foo1 = foo1
                && (*setups)[i].prepare_threshold_verification(
                    positions.len(),
                    &positions,
                    msgs[i],
                    &mut appk,
                    &mut msg_hash,
                    &mut apk,
                    &mut mf_hash_sum,
                );
            ml_g1[2 * i + 1] = appk;
            ml_g2[2 * i + 1] = msg_hash.into();
            ml_g1[2 * i + 2] = apk;
            ml_g2[2 * i + 2] = mf_hash_sum.into();
        }
    }

    let foo2: bool = Gt::identity()
        == multi_miller_loop(
            &ml_g1
                .iter()
                .zip(ml_g2.iter())
                .collect::<Vec<(&G1Affine, &G2Prepared)>>(),
        )
        .final_exponentiation();

    foo1 && foo2
}

pub fn verify_multi_aggregated(
    setups: &[&Setup],
    sigs: &[G2Affine],
    poss: &[&[usize]],
    msgs: &[&[u8]],
) -> bool {
    let n = poss.len();
    assert_eq!(n, sigs.len());
    assert_eq!(n, msgs.len());
    
    let sig: G2Affine = sigs.into_iter().sum_by(G2Projective::from).into();
    
    let mut ml_g1 = vec![G1Affine::identity(); n + 1];
    let mut ml_g2 = vec![G2Affine::identity().into(); n + 1];
    
    ml_g1[0] = -G1Affine::generator();
    ml_g2[0] = sig.into();

    for i in 0..n {
	ml_g1[i+1] = setups[i].apk;
	ml_g2[i+1] = hash_to_g2(msgs[i]).into();
    }

    Gt::identity()
        == multi_miller_loop(
	    &ml_g1.iter().zip(ml_g2.iter())
	                   .collect::<Vec<(&G1Affine, &G2Prepared)>>(),
        )
        .final_exponentiation()
}
