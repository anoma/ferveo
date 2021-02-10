#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]

use crate::{poly, fft};

use bls12_381::Scalar;
use either::Either;
use itertools;
use num::integer::div_ceil;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::convert::TryInto;

pub struct Context {
    /* Map keyed by sha2-256 hashes of commitments.
    The values of the map are pairs of node indexes and scalars */
    A: HashMap<[u8; 32], HashSet<(Scalar, Scalar)>>,
    d: u32, // index of the dealer's public key in the setup
    /* Counters for `echo` messages.
    The keys of the map are sha2-256 hashes. */
    e: HashMap<[u8; 32], u32>,
    f: u32,      // failure threshold
    i: u32,      // index of this node in the setup
    n: u32,      // number of nodes in the setup
    N: u32,      // total weight of all nodes
    W: Vec<u32>, // weights of nodes
    share_indexes: Vec<usize>,
    domain: (Scalar, u32, u64), // FFT domain
    /* Counters for `ready` messages.
    The keys of the map are sha2-256 hashes. */
    r: HashMap<[u8; 32], u32>,
    t: u32,   // threshold
    tau: u32, // session identifier
}

#[derive(Clone)]
/* An "echo" message */
pub struct Echo {
    C: Rc<poly::Public>,
    alpha: Vec<Scalar>,
}

#[derive(Clone, Debug)]
/* A "ready" message */
pub struct Ready {
    C: Rc<poly::Public>,
    alpha: Vec<Scalar>,
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
    C.iter().for_each(|coeff| {
        let coeff_bytes = coeff.to_compressed().to_vec();
        hasher.update(coeff_bytes)
    });
    hasher.finalize().into()
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

/* Increments the value at the given key */
fn incr<K>(k: K, hm: &mut HashMap<K, u32>, w: u32)
where
    K: std::hash::Hash + std::cmp::Eq + Copy,
{
    insert_if_none(k, 0, hm);
    *hm.get_mut(&k).unwrap() += w;
}

impl Context {
    /* Initialize node with
    dealer index `d`,
    failure threshold `f`,
    node index `i`,
    node count `n`,
    threshold `t`,
    and session identifier `tau`. */
    pub fn init(
        d: u32,      // index of the dealer's public key in the setup
        f: u32,      // failure threshold
        i: u32,      // index of this node's public key in the setup
        n: u32,      // the number of nodes in the setup
        N: u32,      // total weight of all nodes
        W: Vec<u32>, // weights of all the nodes
        t: u32,      // threshold
        tau: u32,    // session identifier
    ) -> Self {
        if i >= n {
            panic!(
                "Cannot initialize node with index `{}` with fewer than \
                   `{}` participant node public keys.",
                i,
                i + 1
            )
        }
        if d >= n {
            panic!(
                "Cannot set dealer index to `{}` with fewer than \
                   `{}` participant node public keys.",
                d,
                d + 1
            )
        }
        if t > n {
            panic!(
                "Cannot set threshold to `{t}` with fewer than \
                   `{t}` participant node public keys.",
                t = t
            )
        }
        if t + f > n {
            panic!(
                "Sum of threshold (`{t}`) and failure threshold (`{f}`) \
                    must be less than or equal to the number of participant \
                    nodes (`{n}`)",
                t = t,
                f = f,
                n = n
            )
        }

        let A = HashMap::new();
        let e = HashMap::new();
        let r = HashMap::new();

        let domain = fft::domain(t as usize).unwrap();

        let mut share_indexes = Vec::with_capacity(n as usize);
        let mut total = 0usize;
        for w in W.iter() {
            share_indexes.push(total);
            total += *w as usize;
        }

        Context {
            A,
            d,
            e,
            f,
            i,
            n,
            N,
            r,
            t,
            W,
            domain,
            share_indexes,
            tau,
        }
    }

    /* Respond to a "share" message.
    Should only be processed as the dealer. */
    pub fn share<R: rand::Rng + Sized>(
        &self,
        rng: &mut R,
        Share { s }: Share,
    ) -> ShareResponse {
        let mut phi = poly::random_secret(self.t, rng);
        phi[(0, 0)] = s;
        let C = Rc::new(poly::public(&phi));
        (0..self.n)
            .map(|j| Send {
                C: C.clone(),
                a: poly::share(
                    &phi,
                    Scalar::from(u64::from(j)) * self.domain.0,
                ),
            })
            .collect()
    }

    /* Respond to a "send" message.
    Should only be accepted from the dealer. */
    pub fn send(&self, Send { C, a }: Send) -> SendResponse {
        if poly::verify_share(
            &C,
            &a,
            poly::scalar_exp_u64(self.domain.0, self.i.into()),
        ) {
            /*let shares = (0..self.N)
                .map(|j| {
                    poly::eval_share(
                        &a,
                        poly::scalar_exp_u64(self.domain.0, j.into()),
                    )
                })
                .collect::<Vec<Scalar>>();*/
            let shares = fft::multi_evaluate(&a, self.domain);

            (0usize..self.n as usize)
                .map(|j| Echo {
                    C: C.clone(),
                    alpha: shares[self.share_indexes[j]
                        ..self.share_indexes[j] + self.W[j] as usize]
                        .to_vec(),
                })
                .collect::<Vec<Echo>>()
                .into()
        } else {
            None
        }
    }

    /* Respond to an "echo" message. */
    pub fn echo(&mut self, m: u32, Echo { C, alpha }: &Echo) -> EchoResponse {
        if alpha.iter().enumerate().all(|(j, a)| {
            poly::verify_point(
                &C,
                poly::scalar_exp_u64(self.domain.0, self.i.into()),
                poly::scalar_exp_u64(self.domain.0, (j as u64) + (m as u64)),
                *a,
            )
        }) {
            let C_hash = hash_public_poly(&C);
            insert_if_none(C_hash, HashSet::new(), &mut self.A);
            let mut h = self.A.get_mut(&C_hash).unwrap();
            let mut i = poly::scalar_exp_u64(self.domain.0, m.into());
            for s in alpha.iter() {
                h.insert((i, *s));
                i *= self.domain.0;
            }
            incr(C_hash, &mut self.e, self.W[m as usize]);

            let e_C = *self.e.get(&C_hash).unwrap();
            let r_C = *self.r.get(&C_hash).unwrap_or(&0);

            if e_C >= div_ceil(self.N + self.t + 1, 2) && r_C < self.t + 1 {
                let A_C = self.A.get(&C_hash).unwrap();
                // the points to use for lagrange interpolation
                let points = A_C.iter().map(|(m, a)| (*m, *a));
                let a_bar = poly::lagrange_interpolate(points);
                /*let shares = (0..self.N)
                    .map(|j| {
                        poly::eval_share(
                            &a_bar,
                            poly::scalar_exp_u64(self.domain.0, j.into()),
                        )
                    })
                    .collect::<Vec<Scalar>>();*/
                let shares = fft::multi_evaluate(&a_bar, self.domain);
                (0usize..self.n as usize)
                    .map(|j| Ready {
                        C: C.clone(),
                        alpha: shares[self.share_indexes[j]
                            ..self.share_indexes[j] + self.W[j] as usize]
                            .to_vec(),
                    })
                    .collect::<Vec<Ready>>()
                    .into()
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn ready(
        &mut self,
        m: u32,
        Ready { C, alpha }: &Ready,
    ) -> ReadyResponse {
        if alpha.iter().enumerate().all(|(j, a)| {
            poly::verify_point(
                &C,
                poly::scalar_exp_u64(self.domain.0, self.i.into()),
                poly::scalar_exp_u64(self.domain.0, (j as u64) + (m as u64)),
                *a,
            )
        }) {
            let C_hash = hash_public_poly(&C);
            insert_if_none(C_hash, HashSet::new(), &mut self.A);
            let mut h = self.A.get_mut(&C_hash).unwrap();
            let mut i = poly::scalar_exp_u64(self.domain.0, m.into());
            for s in alpha.iter() {
                h.insert((i, *s));
                i *= self.domain.0;
            }
            incr(C_hash, &mut self.r, self.W[m as usize]);

            let e_C = *self.e.get(&C_hash).unwrap();
            let r_C = *self.r.get(&C_hash).unwrap_or(&0);

            let A_C = self.A.get(&C_hash).unwrap();
            // the points to use for lagrange interpolation
            let points = A_C.iter().map(|(m, a)| (*m, *a));
            let a_bar = poly::lagrange_interpolate(points);

            if e_C < div_ceil(self.N + self.t + 1, 2) && r_C >= self.t + 1 {
                /*let shares = (0..self.N)
                    .map(|j| {
                        poly::eval_share(
                            &a_bar,
                            poly::scalar_exp_u64(self.domain.0, j.into()),
                        )
                    })
                    .collect::<Vec<Scalar>>();*/
                let shares = fft::multi_evaluate(&a_bar, self.domain);
                let ready_messages = (0usize..self.n as usize)
                    .map(|j| Ready {
                        C: C.clone(),
                        alpha: shares[self.share_indexes[j]
                            ..self.share_indexes[j] + (self.W[j] as usize)]
                            .to_vec(),
                    })
                    .collect();

                Some(Either::Left(ready_messages))
            } else if r_C >= self.N - self.t - self.f {
                let s = poly::eval_share(&a_bar, Scalar::zero());
                Some(Either::Right(Shared { C: C.clone(), s }))
            } else {
                None
            }
        } else {
            None
        }
    }
}
