#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]

use crate::bls;
use crate::poly;

use bls12_381::{G1Affine, G1Projective, Scalar};
use num::integer::div_ceil;
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;

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
    pub d: u32,          // the dealer index
    pub s_id: Scalar,    // the share for node i from the dealer
                     // FIXME: add R_d
}

#[derive(Clone)]
pub enum SharedAction {
    Delay,
    Send(Send),
}

pub struct Context {
    /* Counters for `echo` messages.
    The keys of the map are sha2-256 hashes of q sets. */
    e: HashMap<[u8; 32], u32>,
    f: u32,      // failure threshold
    i: u32,      // index of this node's public key in `p`
    l: u32,      // index of the leader's public key in `p`
    l_next: u32, // index of the next leader's public key in `p`
    /* Counters for `lead-ch` messages.
    The index of the map is the leader index. */
    lc: HashMap<u8, u32>,
    lc_flag: bool, // leader count flag
    // FIXME: m_bar
    n: u32,               // number of nodes in the setup
    p: Vec<G1Affine>,       // sorted public keys for all participant nodes
    q_bar: BTreeSet<u32>, // set of node indexes
    q_hat: BTreeSet<u32>, // set of node indexes
    /* Counters for `ready` messages.
    The keys of the map are sha2-256 hashes of (l, q) pairs. */
    r: HashMap<[u8; 32], u32>,
    // FIXME: r_hat
    t: u32,   // threshold
    tau: u32, // session identifier
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
    /* Initialize node with
    failure threshold `f`,
    node index `i`,
    leader index `l`,
    participant node public keys `p`,
    threshold `t`,
    and session identifier `tau`. */
    pub fn init(
        f: u32,       // failure threshold
        i: u32,       // index of this node's public key in `p`
        l: u32,       // index of the leader's public key in `p`
        p: &[G1Affine], // sorted public keys for all participant nodes
        /* signatures on a lead-ch message for the current leader */
        // FIXME: do these all use the same values for q/rm?
        //sigs: &[u32, G2Affine],
        t: u32,   // threshold
        tau: u32, // session identifier
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
        if n <= l {
            panic!(
                "Cannot set leader index to `{}` with fewer than \
                   `{}` participant node public keys.",
                l,
                l + 1
            )
        }
        if n < t {
            panic!(
                "Cannot set threshold to `{t}` with fewer than \
                   `{t}` participant node public keys.",
                t = t,
            )
        }
        if n < t + f {
            panic!(
                "Sum of threshold (`{t}`) and failure threshold (`{f}`) \
                    must be less than or equal to the number of participant \
                    nodes (`{n}`)",
                t = t,
                f = f,
                n = n,
            )
        }
        let p = p.to_vec();
        if !p.iter().is_sorted_by_key(|pk| pk.to_compressed()) {
            panic!("Participant node public keys must be sorted.")
        }

        let e = HashMap::new();
        let l_next = (l + n - 1) % n; //FIXME: is this correct?
        let lc = HashMap::new();
        let lc_flag = false;
        let q_bar = BTreeSet::new();
        let q_hat = BTreeSet::new();
        let r = HashMap::new();

        Context {
            e,
            f,
            i,
            l,
            l_next,
            lc,
            lc_flag,
            n,
            p,
            q_bar,
            q_hat,
            r,
            t,
            tau,
        }
    }

    /* Respond to a "shared" message. */
    pub fn shared(
        &mut self,
        Shared { C, d, s_id }: &Shared,
    ) -> Option<SharedAction> {
        self.q_hat.insert(*d);
        if self.q_hat.len() == (self.t as usize) + 1 && self.q_bar.is_empty() {
            if self.i == self.l {
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
        let lq_hash = hash_LQ(self.l, &q);
        let mut e_LQ = get_mut_or_insert(lq_hash, 0, &mut self.e);
        *e_LQ += 1;
        let r_LQ = *get_or_insert(lq_hash, 0, &mut self.r);
        if *e_LQ == div_ceil(self.n + self.t + 1, 2) && r_LQ < self.t + 1 {
            self.q_bar = self.q_bar.union(&q).cloned().collect();
            // FIXME: What should happen to M-bar?
            Some(Ready { q })
        } else {
            None
        }
    }

    /* Respond to a "ready" message */
    pub fn ready(&mut self, Ready { q }: Ready) -> Option<ReadyAction> {
        let lq_hash = hash_LQ(self.l, &q);
        let mut r_LQ = get_mut_or_insert(lq_hash, 0, &mut self.r);
        *r_LQ += 1;
        let e_LQ = *get_or_insert(lq_hash, 0, &mut self.e);
        if *r_LQ == self.t + 1 && e_LQ < div_ceil(self.n + self.t + 1, 2) {
            self.q_bar = self.q_bar.union(&q).cloned().collect();
            // FIXME: What should happen to M-bar?
            Some(ReadyAction::Ready(Ready { q }))
        } else if *r_LQ == self.n - self.t - self.f {
            Some(ReadyAction::Complete)
        } else {
            None
        }
    }
}

// add two public polynomial commitments
fn add_public(xs: &poly::Public, ys: &poly::Public) -> poly::Public {
    xs.zip_map(&ys, |x, y| {
        let y: G1Projective = y.into();
        (x + y).into()
    })
}

/* Finalize after receiving shared-output messages */
pub fn finalize(shares: &[Shared]) -> (poly::Public, Scalar) {
    let s_i: Scalar = shares.iter().map(|s| s.s_id).sum();
    let C = shares
        .iter()
        .map(|s| s.C.clone())
        .fold_first(|x, y| add_public(&x, &y).into())
        .unwrap();
    let C = Rc::try_unwrap(C).unwrap();
    (C, s_i)
}
