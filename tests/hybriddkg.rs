#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]
//#![feature(bindings_after_at)]

use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use either::Either;
use ferveo::hybriddkg::*;
use ferveo::poly;
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use std::rc::Rc;

mod hybridvss;

type Scalar = Fr;

// Fixed seed for reproducability
fn rng() -> StdRng {
    StdRng::seed_from_u64(0)
}

// A Hybriddkg scheme
struct Scheme {
    params: Params,
    nodes: Vec<Context>,
}

impl Scheme {
    /* Generate a fresh setup with `n` participants,
    failure threshold `f`,
    threshold `t` */
    fn init<R: Rng>(n: u32, f: u32, t: u32, rng: &mut R) -> Self {
        let l: u32 = rng.gen_range(0, n);
        let params = Params { n, f, t, l };
        let nodes = (0..n).map(|i| Context::init(params, i)).collect();
        Scheme { params, nodes }
    }

    // run hybridvss_sh protocol for dealer `d`
    fn hybridvss_sh(&self, d: u32) -> Vec<Shared> {
        let mut rng = StdRng::seed_from_u64(0);
        let Params { f, n, t, .. } = self.params;
        let params = ferveo::hybridvss::Params { d, f, n, t };
        let mut scheme = hybridvss::Scheme::new(params);

        let share = ferveo::hybridvss::sh::Share {
            s: Scalar::rand(&mut rng),
        };
        let sends = scheme.dealer_share(share, &mut rng);
        let echos = scheme.send_valid_each(sends);
        let ready_messages = scheme
            .echo_threshold_each(echos, &mut rng)
            .into_iter()
            .map(|echo_response| echo_response.unwrap())
            .collect();

        scheme
            .ready_threshold_each(ready_messages, &mut rng)
            .into_iter()
            .map(|ready_response| match ready_response {
                Some(Either::Right(ferveo::hybridvss::sh::Shared { C, s })) => {
                    Shared { C, d, s_id: s }
                }
                _ => panic!(),
            })
            .collect()
    }

    // run hybridvss_sh protocol for each dealer
    fn run_hybridvss_sh(&self) -> Vec<Vec<Shared>> {
        // shared messages for each dealer
        let shared_messages: Vec<_> =
            (0..self.params.n).map(|d| self.hybridvss_sh(d)).collect();

        // shared messages from each node
        (0..self.params.n)
            .map(|i| {
                shared_messages
                    .iter()
                    .map(|shared_d| shared_d[i as usize].clone())
                    .collect()
            })
            .collect()
    }
}

#[test]
/* test that the leader sends after enough valid shares,
and the other nodes delay */
fn shared_send_valid() {
    let mut rng = rng();
    let n = 6;
    let t = 4u32;
    let scheme = Scheme::init(n, 0, t, &mut rng);
    let mut nodes = scheme.nodes;
    let l = scheme.params.l;

    // Commitments for each dealer
    let Cs: Vec<_> = (0..n)
        .map(|_| {
            let secret =
                poly::random_secret(t, Scalar::rand(&mut rng), &mut rng);
            Rc::new(poly::public(&secret))
        })
        .collect();

    for (i, node) in nodes.iter_mut().enumerate() {
        /* generate a shared message for each other node.
        the individual shares are expected to be invalid. */
        use rand::seq::IteratorRandom;
        // pairs of node indexes d and commitments
        let shared_messages: Vec<Shared> = Cs
            .iter()
            .cloned()
            .enumerate()
            .map(|(d, C)| Shared {
                C,
                d: (d as u32),
                s_id: Scalar::rand(&mut rng),
            })
            .collect();

        // accept shared messages from t + 1 nodes, in random order
        shared_messages
            .into_iter()
            .choose_multiple(&mut rng, (t + 1) as usize)
            .into_iter()
            .enumerate()
            .for_each(|(count, shared_message)| {
                let shared_response = node.shared(&shared_message);
                if (count as u32) == t {
                    assert!(shared_response.is_some());
                    match shared_response.unwrap() {
                        SharedAction::Delay => assert!(l != (i as u32)),
                        SharedAction::Send(_) => assert!(l == (i as u32)),
                    }
                } else {
                    assert!(shared_response.is_none())
                }
            });
    }
}

#[test]
/* Test that nodes echo on a valid send */
fn send_echo_valid() {
    use rand::seq::IteratorRandom;

    let mut rng = rng();
    let n = 6;
    let t = 4u32;
    let scheme = Scheme::init(n, 0, t, &mut rng);
    let mut nodes = scheme.nodes;
    let l = scheme.params.l;

    // Commitments for each dealer
    let Cs: Vec<_> = (0..n)
        .map(|_| {
            let secret =
                poly::random_secret(t, Scalar::rand(&mut rng), &mut rng);
            Rc::new(poly::public(&secret))
        })
        .collect();

    /* generate a shared message for each other node.
    the individual shares are expected to be invalid. */
    let shared_messages: Vec<Shared> = Cs
        .iter()
        .cloned()
        .enumerate()
        .map(|(d, C)| Shared {
            C,
            d: (d as u32),
            s_id: Scalar::rand(&mut rng),
        })
        .collect();

    // leader accepts shared messages from t + 1 nodes, in random order
    let mut send = None;
    shared_messages
        .into_iter()
        .choose_multiple(&mut rng, (t + 1) as usize)
        .into_iter()
        .for_each(|shared_message| {
            let shared_response = nodes[l as usize].shared(&shared_message);
            match shared_response {
                Some(SharedAction::Send(s)) => send = Some(s),
                _ => (),
            }
        });

    let send = send.unwrap().clone();

    for node in nodes.iter_mut() {
        assert!(node.send(send.clone()).is_some())
    }
}

#[test]
/* Test that nodes return ready messages, given enough valid echos */
fn echo_ready_valid() {
    use rand::seq::IteratorRandom;

    let mut rng = rng();
    let n = 6;
    let t = 4u32;
    let scheme = Scheme::init(n, 0, t, &mut rng);
    let mut nodes = scheme.nodes;
    let l = scheme.params.l;

    // Commitments for each dealer
    let Cs: Vec<_> = (0..n)
        .map(|_| {
            let secret =
                poly::random_secret(t, Scalar::rand(&mut rng), &mut rng);
            Rc::new(poly::public(&secret))
        })
        .collect();

    /* generate a shared message for each other node.
    the individual shares are expected to be invalid. */
    let shared_messages: Vec<Shared> = Cs
        .iter()
        .cloned()
        .enumerate()
        .map(|(d, C)| Shared {
            C,
            d: (d as u32),
            s_id: Scalar::rand(&mut rng),
        })
        .collect();

    // leader accepts shared messages from t + 1 nodes, in random order
    let mut send = None;
    shared_messages
        .into_iter()
        .choose_multiple(&mut rng, (t + 1) as usize)
        .into_iter()
        .for_each(|shared_message| {
            let shared_response = nodes[l as usize].shared(&shared_message);
            match shared_response {
                Some(SharedAction::Send(s)) => send = Some(s),
                _ => (),
            }
        });

    let send = send.unwrap().clone();

    let echos: Vec<Echo> = nodes
        .iter_mut()
        .map(|node| node.send(send.clone()).unwrap())
        .collect();

    for node in nodes.iter_mut() {
        /* choose `ceil ((n+t+1)/2)` echos to accept */
        let threshold = num::integer::div_ceil(n + t + 1, 2) as usize;
        let echos = echos.iter().choose_multiple(&mut rng, threshold);

        for (count, echo) in echos.into_iter().cloned().enumerate() {
            let response = node.echo(echo);
            if count == threshold - 1 {
                assert!(response.is_some())
            } else {
                assert!(response.is_none())
            }
        }
    }
}

//TODO: test ready-ready

#[test]
/* Test that nodes return complete, given enough valid ready messages */
fn ready_complete_valid() {
    use rand::seq::IteratorRandom;

    let mut rng = rng();
    let n = 6;
    let t = 4;
    let f = 0;
    let scheme = Scheme::init(n, f, t, &mut rng);
    let mut nodes = scheme.nodes;
    let l = scheme.params.l;

    // Commitments for each dealer
    let Cs: Vec<_> = (0..n)
        .map(|_| {
            let secret =
                poly::random_secret(t, Scalar::rand(&mut rng), &mut rng);
            Rc::new(poly::public(&secret))
        })
        .collect();

    /* generate a shared message for each other node.
    the individual shares are expected to be invalid. */
    let shared_messages: Vec<Shared> = Cs
        .iter()
        .cloned()
        .enumerate()
        .map(|(d, C)| Shared {
            C,
            d: (d as u32),
            s_id: Scalar::rand(&mut rng),
        })
        .collect();

    // leader accepts shared messages from t + 1 nodes, in random order
    let mut send = None;
    shared_messages
        .into_iter()
        .choose_multiple(&mut rng, (t + 1) as usize)
        .into_iter()
        .for_each(|shared_message| {
            let shared_response = nodes[l as usize].shared(&shared_message);
            match shared_response {
                Some(SharedAction::Send(s)) => send = Some(s),
                _ => (),
            }
        });

    let send = send.unwrap().clone();

    let echos: Vec<Echo> = nodes
        .iter_mut()
        .map(|node| node.send(send.clone()).unwrap())
        .collect();

    let mut ready_messages: Vec<Option<Ready>> = vec![None; n as usize];
    for (i, node) in nodes.iter_mut().enumerate() {
        /* choose `ceil ((n+t+1)/2)` echos to accept */
        let threshold = num::integer::div_ceil(n + t + 1, 2) as usize;
        let echos = echos.iter().choose_multiple(&mut rng, threshold);

        for echo in echos.into_iter().cloned() {
            ready_messages[i] = node.echo(echo);
        }
    }
    assert!(ready_messages.iter().all(|ready| ready.is_some()));
    let ready_messages: Vec<Ready> = ready_messages
        .into_iter()
        .map(|ready| ready.unwrap())
        .collect();

    for node in nodes.iter_mut() {
        /* shuffle the ready_messages */
        let ready_messages =
            ready_messages.iter().choose_multiple(&mut rng, n as usize);

        for (count, ready) in ready_messages.into_iter().cloned().enumerate() {
            let response = node.ready(ready);
            if count == (n - t - f - 1) as usize {
                match response {
                    Some(ReadyAction::Complete) => (),
                    _ => assert!(false),
                }
            } else {
                assert!(response.is_none())
            }
        }
    }
}

#[test]
/* Test that nodes can finalize, given enough valid shared-output messages */
fn shared_output_finalize_valid() {
    use rand::seq::IteratorRandom;

    let mut rng = rng();
    let n = 6;
    let t = 4;
    let f = 0;
    let mut scheme = Scheme::init(n, f, t, &mut rng);
    let l = scheme.params.l;

    let shared_messages = scheme.run_hybridvss_sh();

    /* leader accepts shared messages for t + 1 dealers in random order */
    let mut send = None;
    shared_messages[l as usize]
        .iter()
        .choose_multiple(&mut rng, (t + 1) as usize)
        .into_iter()
        .cloned()
        .for_each(|shared_message| {
            let shared_response =
                scheme.nodes[l as usize].shared(&shared_message);
            match shared_response {
                Some(SharedAction::Send(s)) => send = Some(s),
                _ => (),
            }
        });

    let send = send.unwrap().clone();

    let echos: Vec<Echo> = scheme
        .nodes
        .iter_mut()
        .map(|node| node.send(send.clone()).unwrap())
        .collect();

    let mut ready_messages: Vec<Option<Ready>> = vec![None; n as usize];
    for (i, node) in scheme.nodes.iter_mut().enumerate() {
        /* choose `ceil ((n+t+1)/2)` echos to accept */
        let threshold = num::integer::div_ceil(n + t + 1, 2) as usize;
        let echos = echos.iter().choose_multiple(&mut rng, threshold);

        for echo in echos.into_iter().cloned() {
            ready_messages[i] = node.echo(echo);
        }
    }
    assert!(ready_messages.iter().all(|ready| ready.is_some()));
    let ready_messages: Vec<Ready> = ready_messages
        .into_iter()
        .map(|ready| ready.unwrap())
        .collect();

    for node in scheme.nodes.iter_mut() {
        let threshold = (n - t - f - 1) as usize;
        /* choose `threshold` ready messages */
        let ready_messages =
            ready_messages.iter().choose_multiple(&mut rng, threshold);

        for (count, ready) in ready_messages.into_iter().cloned().enumerate() {
            let response = node.ready(ready);
            if count == threshold {
                match response {
                    Some(ReadyAction::Complete) => (),
                    _ => assert!(false),
                }
            } else {
                assert!(response.is_none())
            }
        }
    }

    // finalize and check that commitments match
    let outputs: Vec<_> = (0..n)
        .map(|i| finalize(&shared_messages[i as usize]))
        .collect();
    let (C_0, _) = &outputs[0];
    assert!(outputs.iter().all(|(C, _)| C == C_0));
}
