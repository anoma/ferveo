#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]

use crate::poly;

use ark_bls12_381::Fr;
use num::integer::div_ceil;
use rand::Rng;
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

#[derive(Clone)]
pub struct Params {
    pub f: u32,      // failure threshold
    pub l: u32,      // leader index
    pub t: u32,      // threshold
    pub w: Vec<u32>, // weight of each participant
}

impl Params {
    pub fn new(f: u32, l: u32, t: u32, w: Vec<u32>) -> Self {
        Params { f, l, t, w }
    }

    // initialize with random values for `l`
    pub fn random_leader<R: Rng>(
        f: u32,
        t: u32,
        w: Vec<u32>,
        rng: &mut R,
    ) -> Self {
        let l = rng.gen_range(0, w.len() as u32);
        Self::new(f, l, t, w)
    }

    // return the number of participants in the setup
    pub fn n(&self) -> u32 {
        self.w.len() as u32
    }

    pub fn total_weight(&self) -> u32 {
        self.w.iter().sum()
    }
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

    pub fn is_leader(&self) -> bool {
        self.i == self.params.l
    }

    /* determine if the threshold has been met,
    in order to broadcast a send message */
    fn shared_send_threshold(&self) -> bool {
        let t = self.params.t as usize;
        let q_bar = &self.q_bar;
        let q_hat_size = self.q_hat.len();
        q_hat_size == t + 1 && q_bar.is_empty()
    }

    /* Respond to a "shared" message. */
    pub fn shared(
        &mut self,
        Shared { d, .. }: &Shared,
    ) -> Option<SharedAction> {
        self.q_hat.insert(*d);
        if self.shared_send_threshold() {
            if self.is_leader() {
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

    // increment the echo counter
    fn incr_echo_counter(&mut self, lq_hash: [u8; 32]) {
        let e_LQ: &mut u32 = get_mut_or_insert(lq_hash, 0, &mut self.e);
        *e_LQ += 1;
    }

    /* determine if the threshold has been met,
    in order to broadcast a ready message */
    fn echo_ready_threshold(&mut self, lq_hash: [u8; 32]) -> bool {
        let t = self.params.t;
        let W = self.params.total_weight();
        let e_LQ = *get_or_insert(lq_hash, 0, &mut self.e);
        let r_LQ = *get_or_insert(lq_hash, 0, &mut self.r);
        // FIXME: should this be >= on e_LQ?
        e_LQ == div_ceil(W + t + 1, 2) && r_LQ < t + 1
    }

    /* Respond to an "echo" message */
    pub fn echo(&mut self, Echo { q }: Echo) -> Option<Ready> {
        let lq_hash = hash_LQ(self.params.l, &q);
        self.incr_echo_counter(lq_hash);
        if self.echo_ready_threshold(lq_hash) {
            self.q_bar = self.q_bar.union(&q).cloned().collect();
            // FIXME: What should happen to M-bar?
            Some(Ready { q })
        } else {
            None
        }
    }

    // increment ready echo counter
    fn incr_ready_counter(&mut self, lq_hash: [u8; 32]) {
        let r_LQ: &mut u32 = get_mut_or_insert(lq_hash, 0, &mut self.r);
        *r_LQ += 1;
    }

    /* determine if the threshold has been met,
    in order to broadcast a ready message */
    fn ready_ready_threshold(&mut self, lq_hash: [u8; 32]) -> bool {
        let t = self.params.t;
        let W = self.params.total_weight();
        let e_LQ = *get_or_insert(lq_hash, 0, &mut self.e);
        let r_LQ = *get_or_insert(lq_hash, 0, &mut self.r);
        // FIXME: should this be >= on r_C?
        r_LQ == t + 1 && e_LQ < div_ceil(W + t + 1, 2)
    }

    /* determine if the threshold has been met,
    in order to complete the dkg */
    fn ready_complete_threshold(&mut self, lq_hash: [u8; 32]) -> bool {
        let Params { t, f, .. } = self.params;
        let W = self.params.total_weight();
        let r_LQ = *get_or_insert(lq_hash, 0, &mut self.r);
        // FIXME: should this be >= on r_C?
        r_LQ == W - t - f
    }

    /* Respond to a "ready" message */
    pub fn ready(&mut self, Ready { q }: Ready) -> Option<ReadyAction> {
        let lq_hash = hash_LQ(self.params.l, &q);
        self.incr_ready_counter(lq_hash);
        if self.ready_ready_threshold(lq_hash) {
            self.q_bar = self.q_bar.union(&q).cloned().collect();
            // FIXME: What should happen to M-bar?
            Some(ReadyAction::Ready(Ready { q }))
        } else if self.ready_complete_threshold(lq_hash) {
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
        .reduce(|x, y| poly::add_public(&x, &y).into())
        .unwrap();
    let C = Rc::try_unwrap(C).unwrap();
    (C, s_i)
}
