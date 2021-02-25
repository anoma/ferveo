#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]

use crate::poly;

use ark_bls12_381::{Fr, G1Affine};
use ark_poly::Polynomial;
use ark_serialize::CanonicalSerialize;
use either::Either;
use num::integer::div_ceil;
use num::Zero;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use crate::hybridvss::params::Params;

type Scalar = Fr;

pub struct Context {
    /* Map keyed by sha2-256 hashes of commitments.
    The values of the map are pairs of node indexes and scalars */
    A: HashMap<[u8; 32], HashSet<(u32, Scalar)>>,
    /* Counters for `echo` messages.
    The keys of the map are sha2-256 hashes. */
    e: HashMap<[u8; 32], u32>,
    i: u32, // index of this node in the setup
    /* Counters for `ready` messages.
    The keys of the map are sha2-256 hashes. */
    params: Params,
    r: HashMap<[u8; 32], u32>,
}

#[derive(Clone)]
/* An "echo" message */
pub struct Echo {
    C: Rc<poly::Public>,
    alpha: Scalar,
}

#[derive(Clone, Debug)]
/* A "ready" message */
pub struct Ready {
    C: Rc<poly::Public>,
    alpha: Scalar,
}

pub type EchoResponse = Option<Vec<Ready>>;

pub type ReadyResponse = Option<Either<Vec<Ready>, Shared>>;

/* A "send" message */
pub struct Send {
    C: Rc<poly::Public>,
    a: poly::Share,
}

pub type SendResponse = Option<Vec<Echo>>;

/* A "share" message */
pub struct Share {
    pub s: Scalar,
}

pub type ShareResponse = Vec<Send>;

/* A "shared" message */
pub struct Shared {
    pub C: Rc<poly::Public>,
    pub s: Scalar,
}

// compute the sha2-256 hash of a public polynomial
fn hash_public_poly(C: &poly::Public) -> [u8; 32] {
    use digest::Digest;
    let mut hasher = sha2::Sha256::new();
    C.iter().for_each(|coeffs| {
        coeffs.iter().for_each(|coeff| {
            let coeff_bytes = compress_G1Affine(coeff);
            hasher.update(coeff_bytes)
        })
    });
    hasher.finalize().into()
}

fn compress_G1Affine(p: &G1Affine) -> [u8; 48] {
    use std::convert::TryInto;
    let mut buf = Vec::new();
    p.serialize(&mut buf).unwrap();
    buf.try_into().unwrap()
}

/* Alters the value at the specified key.
The value is deleted if the function returns `None`. */
fn alter<F, K, V>(f: F, k: K, hm: &mut HashMap<K, V>)
where
    F: FnOnce(Option<V>) -> Option<V>,
    K: std::hash::Hash + std::cmp::Eq,
{
    if let Some(v) = f(hm.remove(&k)) {
        hm.insert(k, v);
    }
}

/* Inserts the value only if no value is associated with the given key. */
fn insert_if_none<K, V>(k: K, v: V, hm: &mut HashMap<K, V>)
where
    K: std::hash::Hash + std::cmp::Eq,
{
    alter(|x| x.unwrap_or(v).into(), k, hm)
}

/* If the key exists in the map,
returns a reference to the value at that key.
Otherwise, inserts the provided value,
and returns a reference to it. */
fn get_or_insert<K, V>(k: K, v: V, m: &mut HashMap<K, V>) -> &V
where
    K: Copy + std::cmp::Eq + std::hash::Hash,
{
    insert_if_none(k, v, m);
    m.get(&k).unwrap()
}

/* Increments the value at the given key */
fn incr<K>(k: K, hm: &mut HashMap<K, u32>)
where
    K: std::hash::Hash + std::cmp::Eq + Copy,
{
    insert_if_none(k, 0, hm);
    *hm.get_mut(&k).unwrap() += 1;
}

impl Context {
    pub fn init(
        params: Params,
        i: u32, // index of this node's public key in the setup
    ) -> Self {
        let A = HashMap::new();
        let e = HashMap::new();
        let r = HashMap::new();

        Context { A, e, i, params, r }
    }

    /* Respond to a "share" message.
    Should only be processed as the dealer. */
    pub fn share<R: rand::Rng + Sized>(
        &self,
        rng: &mut R,
        Share { s }: Share,
    ) -> ShareResponse {
        let phi = poly::random_secret(self.params.t, s, rng);
        let C = Rc::new(poly::public(&phi));
        (0..self.params.n)
            .map(|j| poly::share(&phi, j))
            .map(|a| Send { C: C.clone(), a })
            .collect()
    }

    /* Respond to a "send" message.
    Should only be accepted from the dealer. */
    pub fn send(&self, Send { C, a }: Send) -> SendResponse {
        if poly::verify_share(&C, &a, self.i) {
            let echos = (0..self.params.n)
                .map(|j| a.evaluate(&j.into()))
                .map(|alpha| Echo {
                    C: C.clone(),
                    alpha,
                })
                .collect::<Vec<Echo>>();
            Some(echos)
        } else {
            None
        }
    }

    // return a mutable reference to A_C
    fn get_mut_A_C(&mut self, C_hash: [u8; 32]) -> &mut HashSet<(u32, Scalar)> {
        insert_if_none(C_hash, HashSet::new(), &mut self.A);
        self.A.get_mut(&C_hash).unwrap()
    }

    /* determine if the threshold has been met,
    in order to broadcast ready messages */
    fn echo_ready_threshold(&mut self, C_hash: [u8; 32]) -> bool {
        let Params { n, t, .. } = self.params;
        let e_C = *get_or_insert(C_hash, 0, &mut self.e);
        let r_C = *get_or_insert(C_hash, 0, &mut self.r);
        e_C == div_ceil(n + t + 1, 2) && r_C < t + 1
    }

    fn lagrange_interpolate_A_C(&self, C_hash: [u8; 32]) -> poly::Univar {
        let A_C = self.A.get(&C_hash).unwrap();
        // the points to use for lagrange interpolation
        let points = A_C.iter().map(|(m, a)| ((*m as u64).into(), *a));
        poly::lagrange_interpolate(points)
    }

    /* Respond to an "echo" message. */
    pub fn echo(&mut self, m: u32, Echo { C, alpha }: &Echo) -> EchoResponse {
        if poly::verify_point(&C, self.i, m, *alpha) {
            let C_hash = hash_public_poly(&C);
            incr(C_hash, &mut self.e);
            self.get_mut_A_C(C_hash).insert((m, *alpha));

            if self.echo_ready_threshold(C_hash) {
                let a_bar = self.lagrange_interpolate_A_C(C_hash);
                let ready_messages = (0..self.params.n)
                    .map(|j| a_bar.evaluate(&j.into()))
                    .map(|alpha| Ready {
                        C: C.clone(),
                        alpha,
                    })
                    .collect::<Vec<Ready>>();
                ready_messages.into()
            } else {
                None
            }
        } else {
            None
        }
    }

    /* determine if the threshold has been met,
    in order to broadcast ready messages */
    fn ready_ready_threshold(&mut self, C_hash: [u8; 32]) -> bool {
        let Params { n, t, .. } = self.params;
        let e_C = *get_or_insert(C_hash, 0, &mut self.e);
        let r_C = *get_or_insert(C_hash, 0, &mut self.r);
        e_C < div_ceil(n + t + 1, 2) && r_C == t + 1
    }

    /* determine if the threshold has been met,
    in order to broadcast shared messages */
    fn ready_shared_threshold(&mut self, C_hash: [u8; 32]) -> bool {
        let Params { n, t, f, .. } = self.params;
        let r_C = *get_or_insert(C_hash, 0, &mut self.r);
        r_C == n - t - f
    }

    pub fn ready(
        &mut self,
        m: u32,
        Ready { C, alpha }: &Ready,
    ) -> ReadyResponse {
        if poly::verify_point(&C, self.i, m, *alpha) {
            let C_hash = hash_public_poly(&C);
            incr(C_hash, &mut self.r);
            self.get_mut_A_C(C_hash).insert((m, *alpha));

            let a_bar = self.lagrange_interpolate_A_C(C_hash);

            if self.ready_ready_threshold(C_hash) {
                let ready_messages = (0..self.params.n)
                    .map(|j| a_bar.evaluate(&j.into()))
                    .map(|alpha| Ready {
                        C: C.clone(),
                        alpha,
                    })
                    .collect();
                Some(Either::Left(ready_messages))
            } else if self.ready_shared_threshold(C_hash) {
                let s = a_bar.evaluate(&Scalar::zero());
                Some(Either::Right(Shared { C: C.clone(), s }))
            } else {
                None
            }
        } else {
            None
        }
    }
}
