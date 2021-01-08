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
    n: u32,                                         // number of nodes
    t: u32,                                         // threshold
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
        Some(Ready { lead, q })
    } else {
        None
    }
}

pub enum ReadyAction {
    Ready(Ready),
    Complete,
}

/* Respond to a "ready" message. */
fn ready(
    n: u32,                                         // number of nodes
    t: u32,                                         // threshold
    f: u32,                                         // the failure threshold
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
    if ready_count == t + 1 && echo_count < num::integer::div_ceil(n + t + 1, 2)
    {
        *q_bar = q_bar.union(&q).cloned().collect();
        // FIXME: What should happen to M-bar?
        ReadyAction::Ready(Ready { lead, q }).into()
    } else if ready_count == n - t - f {
        ReadyAction::Complete.into()
    } else {
        None
    }
}

/* Finalize after receiving shared-output messages */
fn finalize(
    q: HashSet<Scalar>,
    shares: HashMap<Scalar, Scalar>, // map of P_d to s_(i, d)
) -> Scalar {
    let s = q.iter().filter_map(|p_d| shares.get(p_d)).product();
    // FIXME: What is supposed to happen with C?
    s
}

pub struct LeadCh {
    l_bar: Scalar,
    q: HashSet<Scalar>,
    r_slash_m: HashSet<Scalar>,
}

pub enum LeadChAction {
    LeadCh(LeadCh),
    Send(Send),
    Delay,
}

fn lead_ch(
    t: u32,         // threshold
    f: u32,         // the failure threshold
    l: &mut Scalar, // the leader
    l_next: &mut Scalar,
    lc_flag: bool,
    lead_ch_counts: &mut HashMap<Scalar, u32>,
    m: HashSet<Scalar>,
    m_bar: &mut HashSet<Scalar>,
    p_i: Scalar, // public key for this node
    q_bar: &mut HashSet<Scalar>,
    q_hat: &mut HashSet<Scalar>,
    r: HashSet<Scalar>,
    r_hat: &mut HashSet<Scalar>,
    LeadCh {
        l_bar,
        q,
        r_slash_m,
    }: LeadCh,
) -> Option<LeadChAction> {
    if !(l_bar > *l && verify_signature(&q, &r_slash_m)) {
        None
    } else {
        let lc_l_bar = lead_ch_counts
            .get(&l_bar)
            .map(|count| count + 1)
            .unwrap_or(1);
        lead_ch_counts.insert(l_bar, lc_l_bar);
        *l_next = std::cmp::min(*l_next, l_bar);
        if r_slash_m == r {
            *q_hat = q_hat.union(&q).cloned().collect();
            *r_hat = r_hat.union(&r).cloned().collect();
        } else {
            *q_bar = q_bar.union(&q).cloned().collect();
            *m_bar = m_bar.union(&m).cloned().collect();
        }
        let lc_l = *lead_ch_counts.get(&l).unwrap_or(&0);
        if lc_l == t + f + 1 && lc_flag == false {
            if q_bar.is_empty() {
                Some(LeadChAction::LeadCh(LeadCh {
                    l_bar: *l_next,
                    q: q_hat.clone(),
                    r_slash_m: r_hat.clone(),
                }))
            } else {
                Some(LeadChAction::LeadCh(LeadCh {
                    l_bar: *l_next,
                    q: q_bar.clone(),
                    r_slash_m: m_bar.clone(),
                }))
            }
        } else if true {
            // FIXME: what happens to m_bar and r_hat here?
            *l = l_bar;
            // FIXME: take predecessor l_next = pred l
            lead_ch_counts.remove(l);
            // FIXME: what should happen to lc_flag???
            if p_i == *l {
                if q_bar.is_empty() {
                    Some(LeadChAction::Send(Send {
                        lead: *l,
                        q: q_hat.clone(),
                        r_slash_m: r_hat.clone(),
                    }))
                } else {
                    Some(LeadChAction::Send(Send {
                        lead: *l,
                        q: q_bar.clone(),
                        r_slash_m: m_bar.clone(),
                    }))
                }
            } else {
                Some(LeadChAction::Delay)
            }
        } else {
            None
        }
    }
}
