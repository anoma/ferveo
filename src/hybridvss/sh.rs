#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]

use crate::{fft, poly};

use ark_bls12_381::{Fr, G1Affine};
use ark_ff::Field;
use ark_poly::{Polynomial, Radix2EvaluationDomain};
use ark_serialize::CanonicalSerialize;
use either::Either;
use num::integer::div_ceil;
use num::Zero;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::rc::Rc;

use crate::hybridvss::params::Params;

type Scalar = Fr;

pub struct Context {
    /* Map keyed by sha2-256 hashes of commitments.
    The values of the map are pairs of node indexes and scalars */
    pub A: HashMap<[u8; 32], HashSet<(Scalar, Scalar)>>,
    /* Counters for `echo` messages.
    The keys of the map are sha2-256 hashes. */
    pub e: HashMap<[u8; 32], u32>,
    pub i: u32, // index of this node in the setup
    pub share_indexes: Vec<usize>,
    pub domain: Radix2EvaluationDomain<Fr>, // FFT domain (group_gen, log_size_of_group, size)
    /* Counters for `ready` messages.
    The keys of the map are sha2-256 hashes. */
    pub params: Params,
    pub r: HashMap<[u8; 32], u32>,
}

#[derive(Clone)]
/* An "echo" message */
pub struct Echo {
    pub C: Rc<poly::Public>,
    pub alpha: Vec<Scalar>,
}

#[derive(Clone, Debug)]
/* A "ready" message */
pub struct Ready {
    pub C: Rc<poly::Public>,
    pub alpha: Vec<Scalar>,
}

pub type EchoResponse = Option<Vec<Ready>>;

pub type ReadyResponse = Option<Either<Vec<Ready>, Shared>>;

/* A "send" message */
pub struct Send {
    pub C: Rc<poly::Public>,
    pub a: poly::Share,
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

// Scalar exponentiation by u64. `exp(x, y) = x^y`
fn scalar_exp_u64(x: Scalar, y: u64) -> Scalar {
    x.pow([u64::to_le(y)])
}

// Scalar exponentiation by u64. `exp(x, y) = x^y`
fn scalar_exp_u32(x: Scalar, y: u32) -> Scalar {
    scalar_exp_u64(x, y.into())
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
fn incr<K>(k: K, hm: &mut HashMap<K, u32>, w: u32)
where
    K: std::hash::Hash + std::cmp::Eq + Copy,
{
    insert_if_none(k, 0, hm);
    *hm.get_mut(&k).unwrap() += w;
}

impl Context {
    pub fn init(
        params: Params,
        i: u32, // index of this node's public key in the setup
    ) -> Self {
        let A = HashMap::new();
        let e = HashMap::new();
        let r = HashMap::new();

        let domain = fft::domain(params.total_weight() as usize);

        let mut share_indexes = Vec::with_capacity(params.n() as usize);
        let mut total = 0usize;
        for weight in params.w.iter() {
            share_indexes.push(total);
            total += *weight as usize;
        }

        Context {
            A,
            domain,
            e,
            i,
            params,
            r,
            share_indexes,
        }
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
        (0..self.params.n())
            .map(|j| {
                poly::share(
                    &phi,
                    scalar_exp_u64(self.domain.group_gen, j as u64),
                )
            })
            .map(|a| Send { C: C.clone(), a })
            .collect()
    }

    pub fn verify_share(&self, Send { C, a }: &Send) -> bool {
        let i = scalar_exp_u32(self.domain.group_gen, self.i);
        poly::verify_share(&C, &a, i)
    }

    /* Respond to a "send" message.
    Should only be accepted from the dealer. */
    pub fn send(&self, send: Send) -> SendResponse {
        if self.verify_share(&send) {
            let Send { C, a } = send;
            let shares = a.evaluate_over_domain_by_ref(self.domain).evals;

            let echos = (0usize..self.params.n() as usize)
                .map(|j| {
                    shares[self.share_indexes[j]
                        ..self.share_indexes[j] + self.params.w[j] as usize]
                        .to_vec()
                })
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
    fn get_mut_A_C(
        &mut self,
        C_hash: [u8; 32],
    ) -> &mut HashSet<(Scalar, Scalar)> {
        insert_if_none(C_hash, HashSet::new(), &mut self.A);
        self.A.get_mut(&C_hash).unwrap()
    }

    /* determine if the threshold has been met,
    in order to broadcast ready messages */
    fn echo_ready_threshold(&mut self, C_hash: [u8; 32]) -> bool {
        let t = self.params.t;
        let W = self.params.total_weight();
        let e_C = *get_or_insert(C_hash, 0, &mut self.e);
        let r_C = *get_or_insert(C_hash, 0, &mut self.r);
        e_C >= div_ceil(W + t + 1, 2) && r_C < t + 1
    }

    fn lagrange_interpolate_A_C(&self, C_hash: [u8; 32]) -> poly::Univar {
        let A_C = self.A.get(&C_hash).unwrap();
        poly::lagrange_interpolate(A_C.clone())
    }

    pub fn verify_point(
        &self,
        m: u32,
        C: &poly::Public,
        alpha: &Vec<Scalar>,
    ) -> bool {
        alpha.iter().enumerate().all(|(j, a)| {
            poly::verify_point(
                &C,
                scalar_exp_u32(self.domain.group_gen, self.i),
                scalar_exp_u64(self.domain.group_gen, (j as u64) + (m as u64)),
                *a,
            )
        })
    }

    /* Respond to an "echo" message. */
    pub fn echo(&mut self, m: u32, Echo { C, alpha }: &Echo) -> EchoResponse {
        if self.verify_point(m, C, alpha) {
            let C_hash = hash_public_poly(C);
            incr(C_hash, &mut self.e, self.params.w[m as usize]);

            let domain_0 = self.domain.group_gen;
            let A_C = self.get_mut_A_C(C_hash);
            let mut i = scalar_exp_u32(domain_0, m);
            for s in alpha.iter() {
                A_C.insert((i, *s));
                i *= domain_0;
            }

            if self.echo_ready_threshold(C_hash) {
                let a_bar = self.lagrange_interpolate_A_C(C_hash);
                let shares =
                    a_bar.evaluate_over_domain_by_ref(self.domain).evals;
                let ready_messages = (0usize..self.params.n() as usize)
                    .map(|j| {
                        shares[self.share_indexes[j]
                            ..self.share_indexes[j] + self.params.w[j] as usize]
                            .to_vec()
                    })
                    .map(|alpha| Ready {
                        C: C.clone(),
                        alpha,
                    })
                    .collect::<Vec<Ready>>();
                Some(ready_messages)
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
        let t = self.params.t;
        let W = self.params.total_weight();
        let e_C = *get_or_insert(C_hash, 0, &mut self.e);
        let r_C = *get_or_insert(C_hash, 0, &mut self.r);
        e_C < div_ceil(W + t + 1, 2) && r_C == t + 1
    }

    /* determine if the threshold has been met,
    in order to broadcast shared messages */
    fn ready_shared_threshold(&mut self, C_hash: [u8; 32]) -> bool {
        let Params { t, f, .. } = self.params;
        let W = self.params.total_weight();
        let r_C = *get_or_insert(C_hash, 0, &mut self.r);
        r_C >= W - t - f
    }

    pub fn ready(
        &mut self,
        m: u32,
        Ready { C, alpha }: &Ready,
    ) -> ReadyResponse {
        if self.verify_point(m, C, alpha) {
            let C_hash = hash_public_poly(&C);
            incr(C_hash, &mut self.r, self.params.w[m as usize]);

            let domain_0 = self.domain.group_gen;
            let A_C = self.get_mut_A_C(C_hash);
            let mut i = scalar_exp_u32(domain_0, m);
            for s in alpha.iter() {
                A_C.insert((i, *s));
                i *= domain_0;
            }

            let a_bar = self.lagrange_interpolate_A_C(C_hash);

            if self.ready_ready_threshold(C_hash) {
                let shares =
                    a_bar.evaluate_over_domain_by_ref(self.domain).evals;

                let ready_messages = (0usize..self.params.n() as usize)
                    .map(|j| {
                        shares[self.share_indexes[j]
                            ..self.share_indexes[j]
                                + (self.params.w[j] as usize)]
                            .to_vec()
                    })
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
