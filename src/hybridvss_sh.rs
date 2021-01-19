#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]

use crate::poly;

use bls12_381::{G1Affine, Scalar};
use either::Either;
use num::integer::div_ceil;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

pub struct Context {
    /* Map keyed by sha2-256 hashes of commitments.
    The values of the map are pairs of node indexes and scalars */
    A: HashMap<[u8; 32], HashSet<(u32, Scalar)>>,
    d: u32, // index of the dealer's public key in `p`
    /* Counters for `echo` messages.
    The keys of the map are sha2-256 hashes. */
    e: HashMap<[u8; 32], u32>,
    f: u32,           // failure threshold
    i: u32,           // index of this node's public key in `p`
    n: u32,           // number of nodes in the setup
    p: Vec<G1Affine>, // sorted public keys for all participant nodes
    /* Counters for `ready` messages.
    The keys of the map are sha2-256 hashes. */
    r: HashMap<[u8; 32], u32>,
    t: u32,   // threshold
    tau: u32, // session identifier
}

/* An "echo" message */
pub struct Echo {
    C: Rc<poly::Public>,
    alpha: Scalar,
}

/* A "ready" message */
pub struct Ready {
    C: Rc<poly::Public>,
    alpha: Scalar,
}

type ReadyResponse = Either<Vec<Ready>, Shared>;

/* A "send" message */
pub struct Send {
    C: Rc<poly::Public>,
    a: poly::Share,
}

/* A "share" message */
pub struct Share {
    pub s: Scalar,
}

/* A "shared" message */
pub struct Shared {
    C: Rc<poly::Public>,
    s: Scalar,
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
fn incr<K>(k: K, hm: &mut HashMap<K, u32>)
where
    K: std::hash::Hash + std::cmp::Eq + Copy,
{
    insert_if_none(k, 0, hm);
    *hm.get_mut(&k).unwrap() += 1;
}

impl Context {
    /* Initialize node with
    dealer index `d`,
    failure threshold `f`,
    node index `i`,
    participant node public keys `p`,
    threshold `t`,
    and session identifier `tau`. */
    pub fn init(
        d: u32,         // index of the dealer's public key in `p`
        f: u32,         // failure threshold
        i: u32,         // index of this node's public key in `p`
        p: &[G1Affine], // sorted public keys for all participant nodes
        t: u32,         // threshold
        tau: u32,       // session identifier
    ) -> Self {
        use std::convert::TryInto;
        let n: u32 = p.len().try_into().unwrap();
        if n <= i {
            panic!(
                "Cannot initialize node with index `{}` with fewer than \
                   `{}` participant node public keys.",
                i,
                i + 1
            )
        }
        if n <= d {
            panic!(
                "Cannot set dealer index to `{}` with fewer than \
                   `{}` participant node public keys.",
                d,
                d + 1
            )
        }
        if n < t {
            panic!(
                "Cannot set threshold to `{t}` with fewer than \
                   `{t}` participant node public keys.",
                t = t
            )
        }
        if n < t + f {
            panic!(
                "Sum of threshold (`{t}`) and failure threshold (`{f}`) \
                    must be less than or equal to the number of participant \
                    nodes (`{n}`)",
                t = t,
                f = f,
                n = n
            )
        }
        let p = p.to_vec();
        if !p.iter().is_sorted_by_key(|pk| pk.to_compressed()) {
            panic!("Participant node public keys must be sorted.")
        }

        let A = HashMap::new();
        let e = HashMap::new();
        let r = HashMap::new();

        Context {
            A,
            d,
            e,
            f,
            i,
            n,
            p,
            r,
            t,
            tau,
        }
    }

    /* Respond to a "share" message.
    Should only be processed as the dealer. */
    pub fn share<R: rand::Rng + Sized>(
        &self,
        rng: &mut R,
        Share { s }: Share,
    ) -> Vec<Send> {
        let mut phi = poly::random_secret(self.t, rng);
        phi[(0, 0)] = s;
        let C = Rc::new(poly::public(&phi));
        (0..self.n)
            .map(|j| Send {
                C: C.clone(),
                a: poly::share(&phi, j),
            })
            .collect()
    }

    /* Respond to a "send" message.
    Should only be accepted from the dealer. */
    pub fn send(&self, Send { C, a }: Send) -> Option<Vec<Echo>> {
        if poly::verify_share(&C, &a, self.i) {
            (0..self.n)
                .map(|j| Echo {
                    C: C.clone(),
                    alpha: poly::eval_share(&a, j.into()),
                })
                .collect::<Vec<Echo>>()
                .into()
        } else {
            None
        }
    }

    /* Respond to an "echo" message. */
    pub fn echo(
        &mut self,
        m: u32,
        Echo { C, alpha }: Echo,
    ) -> Option<Vec<Ready>> {
        if poly::verify_point(&C, self.i, m, alpha) {
            let C_hash = hash_public_poly(&C);
            insert_if_none(C_hash, HashSet::new(), &mut self.A);
            self.A.get_mut(&C_hash).unwrap().insert((m, alpha));
            incr(C_hash, &mut self.e);

            let e_C = *self.e.get(&C_hash).unwrap();
            let r_C = *self.r.get(&C_hash).unwrap_or(&0);

            if e_C == div_ceil(self.n + self.t + 1, 2) && r_C < self.t + 1 {
                let A_C = self.A.get(&C_hash).unwrap();
                // the points to use for lagrange interpolation
                let points =
                    A_C.iter().map(|(m, a)| (u64::from(*m).into(), *a));
                let a_bar = poly::lagrange_interpolate(points);
                (0..self.n)
                    .map(|j| Ready {
                        C: C.clone(),
                        alpha: poly::eval_share(&a_bar, j.into()),
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
        Ready { C, alpha }: Ready,
    ) -> Option<ReadyResponse> {
        if poly::verify_point(&C, self.i, m, alpha) {
            let C_hash = hash_public_poly(&C);
            insert_if_none(C_hash, HashSet::new(), &mut self.A);
            self.A.get_mut(&C_hash).unwrap().insert((m, alpha));
            incr(C_hash, &mut self.r);

            let e_C = *self.e.get(&C_hash).unwrap();
            let r_C = *self.r.get(&C_hash).unwrap_or(&0);

            let A_C = self.A.get(&C_hash).unwrap();
            // the points to use for lagrange interpolation
            let points = A_C.iter().map(|(m, a)| (u64::from(*m).into(), *a));
            let a_bar = poly::lagrange_interpolate(points);

            if e_C < div_ceil(self.n + self.t + 1, 2) && r_C == self.t + 1 {
                let ready_messages = (0..self.n)
                    .map(|j| Ready {
                        C: C.clone(),
                        alpha: poly::eval_share(&a_bar, j.into()),
                    })
                    .collect();
                Some(Either::Left(ready_messages))
            } else if r_C == self.n - self.t - self.f {
                let s = poly::eval_share(&a_bar, Scalar::zero());
                Some(Either::Right(Shared { C, s }))
            } else {
                None
            }
        } else {
            None
        }
    }
}
