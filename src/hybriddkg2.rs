#![allow(clippy::many_single_char_names)]

use crate::bls;
use crate::poly;

use bls12_381::{G1Projective, G2Affine, Scalar};
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap, HashSet};

/* A "lead-ch" (leader change) message */
pub struct LeadCh {
    l: u32, // the proposed leader index
    /* map keyed with node indexes, and signature values */
    qrm: BTreeMap<u32, G2Affine>,
    tau: u32, // session identifier
}

impl LeadCh {
    pub fn encode_for_signing(&self) -> Vec<u8> {
        let header_bytes = &b"lead-ch"[..];
        let tau_bytes = &self.tau.to_le_bytes();
        let l_bytes = &self.l.to_le_bytes();
        fn encode_pair((i, s): (&u32, &G2Affine)) -> Vec<u8> {
            let i_bytes = i.to_le_bytes();
            let s_bytes = s.to_compressed();
            i_bytes.iter().chain(s_bytes.iter()).cloned().collect()
        };
        let qrm_bytes: Vec<u8> =
            self.qrm.iter().flat_map(encode_pair).collect();
        [header_bytes, tau_bytes, l_bytes, &qrm_bytes].concat()
    }

    // sign a lead-ch message
    pub fn sign(&self, keys: &bls::Keypair) -> G2Affine {
        bls::sign_g2(keys.secret, &self.encode_for_signing())
    }
}

/* A "send" message */
pub struct Send {
    l: u32, // the leader index
    q: HashSet<u32>, // a set of node indexes
            // FIXME: add r/m
}

/* A "shared" message */
pub struct Shared {
    cd: Scalar, // a dealer commitment
    d: u32,     // the dealer index
    sid: Scalar, // the share for node i from the dealer
                // FIXME: add rd
}

pub enum SharedAction {
    Delay,
    Send(Send),
}

pub struct Context {
    /* Counters for `echo` messages.
    The keys of the map are sha2-256 hashes of (l, q) pairs. */
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
    n: u32,              // number of nodes in the setup
    p: Vec<Scalar>,      // sorted public keys for all participant nodes
    q_bar: HashSet<u32>, // set of node indexes
    q_hat: HashSet<u32>, // set of node indexes
    /* Counters for `ready` messages.
    The keys of the map are sha2-256 hashes of (l, q) pairs. */
    r: HashMap<[u8; 32], u32>,
    // FIXME: r_hat
    t: u32,   // threshold
    tau: u32, // session identifier
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
        p: &[Scalar], // sorted public keys for all participant nodes
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

        let e = HashMap::new();
        let l_next = (l + n - 1) % n; //FIXME: is this correct?
        let lc = HashMap::new();
        let lc_flag = false;
        let q_bar = HashSet::new();
        let q_hat = HashSet::new();
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
    fn shared(
        &mut self,
        Shared { cd, d, sid }: Shared,
    ) -> Option<SharedAction> {
        self.q_hat.insert(d);
        if self.q_hat.len() == (self.t as usize) + 1 && self.q_bar.is_empty() {
            if self.i == self.l {
                Some(SharedAction::Send(Send {
                    l: self.l,
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
}
