#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]

use crate::poly;

use bls12_381::Scalar;
use nalgebra::base::DVector;
use std::collections::{HashMap, HashSet};

pub struct Context {
    /* Map keyed by sha2-256 hashes of commitments.
    The values of the map are pairs of node indexes and scalars */
    A: HashMap<[u8; 32], HashSet<(u32, Scalar)>>,
    d: u32, // index of the dealer's public key in `p`
    /* Counters for `echo` messages.
    The keys of the map are sha2-256 hashes. */
    e: HashMap<[u8; 32], u32>,
    f: u32,         // failure threshold
    i: u32,         // index of this node's public key in `p`
    n: u32,         // number of nodes in the setup
    p: Vec<Scalar>, // sorted public keys for all participant nodes
    /* Counters for `ready` messages.
    The keys of the map are sha2-256 hashes. */
    r: HashMap<[u8; 32], u32>,
    t: u32,   // threshold
    tau: u32, // session identifier
}

/* An "echo" message */
pub struct Echo {
    C: poly::Public,
    alpha: Scalar,
}

/* The response data for a "echo" message.
Can be converted into a distinct `Ready` for each node. */
pub struct EchoResponse {
    C: poly::Public,
    alpha: Vec<Scalar>,
}

/* A "ready" message */
pub struct Ready {
    C: poly::Public,
    alpha: Scalar,
}

/* A "send" message */
pub struct Send {
    C: poly::Public,
    a: poly::Share,
}

/* The response data for a "send" message.
Can be converted into a distinct `Echo` for each node. */
pub struct SendResponse {
    C: poly::Public,
    alpha: Vec<Scalar>,
}

/* A "share" message */
pub struct Share {
    s: Scalar,
}

/* The response data for a "share" message.
Can be converted into a distinct `Send` for each node. */
pub struct ShareResponse {
    C: poly::Public,
    a: Vec<poly::Share>,
}

/* A "shared" message */
pub struct Shared {
    C: poly::Public,
    s: Scalar,
}

/* The response data for a "ready" message */
pub enum ReadyResponse {
    Ready { C: poly::Public, alpha: Vec<Scalar> },
    Shared(Shared),
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
        d: u32,       // index of the dealer's public key in `p`
        f: u32,       // failure threshold
        i: u32,       // index of this node's public key in `p`
        p: &[Scalar], // sorted public keys for all participant nodes
        t: u32,       // threshold
        tau: u32,     // session identifier
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
                   `{t}` participant node public keys."
            )
        }
        if n < t + f {
            panic!(
                "Sum of threshold (`{t}`) and failure threshold (`{f}`) \
                    must be less than or equal to the number of participant \
                    nodes (`{n}`)"
            )
        }
        let p = p.to_vec();
        // TODO: use is_sorted once this is stable
        let mut p_sorted = p.clone();
        p_sorted.sort_unstable();
        if p != p_sorted {
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
    ) -> ShareResponse {
        let mut phi = poly::random_secret(self.t, rng);
        phi[(0, 0)] = s;
        let C = poly::public(&phi);
        let a = (0..self.n).map(|j| poly::share(&phi, j)).collect();
        ShareResponse { a, C }
    }

    /* Respond to a "send" message.
    Should only be accepted from the dealer. */
    pub fn send(&self, Send { C, a }: Send) -> Option<SendResponse> {
        if poly::verify_share(&C, &a, self.i) {
            let alpha = (0..self.n)
                .map(|j| poly::eval_share(&a, u64::from(j).into()))
                .collect();
            Some(SendResponse { C, alpha })
        } else {
            None
        }
    }

    /* Respond to an "echo" message. */
    pub fn echo(
        &mut self,
        m: u32,
        Echo { C, alpha }: Echo,
    ) -> Option<EchoResponse> {
        if poly::verify_point(&C, self.i, m, alpha) {
            let C_hash = hash_public_poly(&C);
            insert_if_none(C_hash, HashSet::new(), &mut self.A);
            self.A.get_mut(&C_hash).unwrap().insert((m, alpha));
            incr(C_hash, &mut self.e);

            let e_C = *self.e.get(&C_hash).unwrap();
            let r_C = *self.r.get(&C_hash).unwrap_or(&0);

            if e_C == num::integer::div_ceil(self.n + self.t + 1, 2)
                && r_C < self.t + 1
            {
                let A_C = self.A.get(&C_hash).unwrap();
                // the points to use for lagrange interpolation
                let points = A_C
                    .iter()
                    .map(|(m, a)| (u64::from(*m).into(), *a))
                    .collect();
                let points = DVector::from_vec(points);
                let a_bar = poly::lagrange_interpolate(&points);
                let alpha = (0..self.n)
                    .map(|j| poly::eval_share(&a_bar, u64::from(j).into()))
                    .collect::<Vec<Scalar>>();
                Some(EchoResponse { C, alpha })
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
            let points = A_C
                .iter()
                .map(|(m, a)| (u64::from(*m).into(), *a))
                .collect();
            let points = DVector::from_vec(points);
            let a_bar = poly::lagrange_interpolate(&points);

            if e_C < num::integer::div_ceil(self.n + self.t + 1, 2)
                && r_C == self.t + 1
            {
                let alpha = (0..self.n)
                    .map(|j| poly::eval_share(&a_bar, u64::from(j).into()))
                    .collect::<Vec<Scalar>>();
                Some(ReadyResponse::Ready { C, alpha })
            } else if r_C == self.n - self.t - self.f {
                let s = poly::eval_share(&a_bar, Scalar::zero());
                Some(ReadyResponse::Shared(Shared { C, s }))
            } else {
                None
            }
        } else {
            None
        }
    }
}
