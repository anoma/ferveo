#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]

use crate::poly;

use ark_bls12_381::Fr;
use num::integer::div_ceil;
use std::collections::{BTreeSet, HashMap};
use std::rc::Rc;

type Scalar = Fr;

/* An "echo" message */
#[derive(Clone)]
pub struct Echo {
    q: BTreeSet<u32>, // a set of node indexes
                      // FIXME: add r/m
}

/* A "ready" message */
#[derive(Clone)]
pub struct Ready {
    q: BTreeSet<u32>, // a set of node indexes
                      // FIXME: add r/m
}

pub enum ReadyAction {
    Ready(Ready),
    Complete,
}

/* A "send" message */
#[derive(Clone)]
pub struct Send {
    q: BTreeSet<u32>, // a set of node indexes
                      // FIXME: add r/m
}

/* A "shared" message */
#[derive(Clone)]
pub struct Shared {
    pub C: Rc<poly::Public>, // a dealer commitment
    pub d: u32,              // the dealer index
    pub s_id: Scalar,        // the share for node i from the dealer
                             // FIXME: add R_d
}

#[derive(Clone)]
pub enum SharedAction {
    Delay,
    Send(Send),
}

#[derive(Copy, Clone)]
pub struct Params {
    pub f: u32, // failure threshold
    pub l: u32, // leader index
    pub n: u32, // number of participants
    pub t: u32, // threshold
}

pub struct Context {
    /* Counters for `echo` messages.
    The keys of the map are sha2-256 hashes of q sets. */
    e: HashMap<[u8; 32], u32>,
    i: u32, // index of this node's public key
    // FIXME: m_bar
    params: Params,
    q_bar: BTreeSet<u32>, // set of node indexes
    q_hat: BTreeSet<u32>, // set of node indexes
    /* Counters for `ready` messages.
    The keys of the map are sha2-256 hashes of (l, q) pairs. */
    r: HashMap<[u8; 32], u32>,
    // FIXME: r_hat
}

/* Inserts the provided value if the key is not present in the map. */
fn insert_if_none<K, V>(k: K, v: V, m: &mut HashMap<K, V>)
where
    K: std::cmp::Eq + std::hash::Hash,
{
    if !m.contains_key(&k) {
        m.insert(k, v);
    }
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

/* If the key exists in the map,
returns a mutable reference to the value at that key.
Otherwise, inserts the provided value,
and returns a mutable reference to it. */
fn get_mut_or_insert<K, V>(k: K, v: V, m: &mut HashMap<K, V>) -> &mut V
where
    K: Copy + std::cmp::Eq + std::hash::Hash,
{
    insert_if_none(k, v, m);
    m.get_mut(&k).unwrap()
}

// Hash an (L, Q) pair
fn hash_LQ(L: u32, Q: &BTreeSet<u32>) -> [u8; 32] {
    use digest::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(L.to_le_bytes());
    Q.iter().for_each(|j| hasher.update(j.to_le_bytes()));
    hasher.finalize().into()
}

impl Context {
    /* Initialize node `i` with `params` */
    pub fn init(
        params: Params,
        i: u32, // index of this node
    ) -> Self {
        let e = HashMap::new();
        let q_bar = BTreeSet::new();
        let q_hat = BTreeSet::new();
        let r = HashMap::new();

        Context {
            e,
            i,
            params,
            q_bar,
            q_hat,
            r,
        }
    }

    /* Respond to a "shared" message. */
    pub fn shared(
        &mut self,
        Shared { d, .. }: &Shared,
    ) -> Option<SharedAction> {
        self.q_hat.insert(*d);
        if self.q_hat.len() == (self.params.t as usize) + 1
            && self.q_bar.is_empty()
        {
            if self.i == self.params.l {
                Some(SharedAction::Send(Send {
                    q: self.q_hat.clone(),
                    // FIXME: add r/m
                }))
            } else {
                Some(SharedAction::Delay)
            }
        } else {
            None
        }
    }

    /* Respond to a "send" message */
    pub fn send(&self, Send { q }: Send) -> Option<Echo> {
        // FIXME: verify-signatures
        if self.q_bar.is_empty() || self.q_bar == q {
            Some(Echo { q })
        } else {
            None
        }
    }

    /* Respond to an "echo" message */
    pub fn echo(&mut self, Echo { q }: Echo) -> Option<Ready> {
        let lq_hash = hash_LQ(self.params.l, &q);
        let mut e_LQ = *get_mut_or_insert(lq_hash, 0, &mut self.e);
        e_LQ += 1;
        let r_LQ = *get_or_insert(lq_hash, 0, &mut self.r);
        if e_LQ == div_ceil(self.params.n + self.params.t + 1, 2)
            && r_LQ < self.params.t + 1
        {
            self.q_bar = self.q_bar.union(&q).cloned().collect();
            // FIXME: What should happen to M-bar?
            Some(Ready { q })
        } else {
            None
        }
    }

    /* Respond to a "ready" message */
    pub fn ready(&mut self, Ready { q }: Ready) -> Option<ReadyAction> {
        let lq_hash = hash_LQ(self.params.l, &q);
        let mut r_LQ = *get_mut_or_insert(lq_hash, 0, &mut self.r);
        r_LQ += 1;
        let e_LQ = *get_or_insert(lq_hash, 0, &mut self.e);
        if r_LQ == self.params.t + 1
            && e_LQ < div_ceil(self.params.n + self.params.t + 1, 2)
        {
            self.q_bar = self.q_bar.union(&q).cloned().collect();
            // FIXME: What should happen to M-bar?
            Some(ReadyAction::Ready(Ready { q }))
        } else if r_LQ == self.params.n - self.params.t - self.params.f {
            Some(ReadyAction::Complete)
        } else {
            None
        }
    }
}

/* Finalize after receiving shared-output messages */
pub fn finalize(shares: &[Shared]) -> (poly::Public, Scalar) {
    let s_i: Scalar = shares.iter().map(|s| s.s_id).sum();
    let C = shares
        .iter()
        .map(|s| s.C.clone())
        .fold_first(|x, y| poly::add_public(&x, &y).into())
        .unwrap();
    let C = Rc::try_unwrap(C).unwrap();
    (C, s_i)
}
