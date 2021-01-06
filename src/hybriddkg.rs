#![allow(clippy::many_single_char_names)]

use crate::poly;

use bls12_381::{G1Projective, Scalar};
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};

pub struct Send {
    lead: Scalar,
    q: HashSet<Scalar>,
    r_slash_m: HashSet<Scalar>,
}

pub enum SharedAction {
    Delay,
    Send(Send),
}

/* Respond to a "shared" message. */
pub fn shared(
    lead: Scalar, // public key for the leader
    p_i: Scalar,  // public key for this node
    t: u32,       // threshold
    q_hat: &mut HashSet<Scalar>,
    r_hat: &mut HashSet<Scalar>,
    q_bar: &mut HashSet<Scalar>,
    p_d: Scalar, // public key for the dealer
    r_d: Scalar,
) -> Option<SharedAction> {
    q_hat.insert(p_d);
    r_hat.insert(r_d);
    if q_hat.len() == (t as usize) + 1 && q_bar.is_empty() {
        if p_i == lead {
            SharedAction::Send(Send {
                lead,
                q: q_hat.clone(),
                r_slash_m: r_hat.clone(),
            })
            .into()
        } else {
            Some(SharedAction::Delay)
        }
    } else {
        None
    }
}

// FIXME: What is this supposed to do???
fn verify_signature(q: &HashSet<Scalar>, _r_slash_m: &HashSet<Scalar>) -> bool {
    true
}

pub struct Echo {
    lead: Scalar,
    q: HashSet<Scalar>,
}

/* Respond to a "send" message. */
pub fn send(
    q_bar: &HashSet<Scalar>,
    Send { lead, q, r_slash_m }: Send,
) -> Option<Echo> {
    if verify_signature(&q, &r_slash_m) && (q_bar.is_empty() || *q_bar == q) {
        Some(Echo { lead, q })
    } else {
        None
    }
}

pub struct Ready {
    lead: Scalar,
    q: HashSet<Scalar>,
}

/* Respond to an "echo" message. */
fn echo(
    n: u32, // number of nodes
    t: u32, // threshold
    echo_counts: &mut HashMap<(Scalar, u64), u32>, // FIXME: is 64 bits appropriate?
    ready_counts: &mut HashMap<(Scalar, u64), u32>, // FIXME: is 64 bits appropriate?
    q_bar: &mut HashSet<Scalar>,
    Echo { lead, q }: Echo,
) -> Option<Ready> {
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    q.iter().for_each(|pk| pk.hash(&mut hasher));
    let q_hash = hasher.finish();
    let echo_count = echo_counts
        .get(&(lead, q_hash))
        .map(|count| count + 1)
        .unwrap_or(1);
    echo_counts.insert((lead, q_hash), echo_count);
    let ready_count = *ready_counts.get(&(lead, q_hash)).unwrap_or(&0);
    if echo_count == num::integer::div_ceil(n + t + 1, 2) && ready_count < t + 1
    {
        *q_bar = q_bar.union(&q).cloned().collect();
        // FIXME: What should happen to M-bar?
        Some(Ready{lead, q})
    } else {
        None
    }
}

pub enum ReadyAction {
    Ready(Ready),
    Complete
}

/* Respond to a "ready" message. */
fn ready(
    n: u32, // number of nodes
    t: u32, // threshold
    f: u32, // the failure threshold
    echo_counts: &mut HashMap<(Scalar, u64), u32>, // FIXME: is 64 bits appropriate?
    ready_counts: &mut HashMap<(Scalar, u64), u32>, // FIXME: is 64 bits appropriate?
    q_bar: &mut HashSet<Scalar>,
    Ready { lead, q }: Ready,
) -> Option<ReadyAction> {
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    q.iter().for_each(|pk| pk.hash(&mut hasher));
    let q_hash = hasher.finish();
    let ready_count = ready_counts
        .get(&(lead, q_hash))
        .map(|count| count + 1)
        .unwrap_or(1);
    ready_counts.insert((lead, q_hash), ready_count);
    let echo_count = *echo_counts.get(&(lead, q_hash)).unwrap_or(&0);
    if ready_count == t + 1
       && echo_count < num::integer::div_ceil(n+t+1, 2) {
        *q_bar = q_bar.union(&q).cloned().collect();
        // FIXME: What should happen to M-bar?
        ReadyAction::Ready(Ready {lead, q}).into()
    } else if ready_count == n - t - f {
        ReadyAction::Complete.into()
    } else {
        None
    }
}
