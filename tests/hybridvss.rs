#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]

use bls12_381::{G1Affine, Scalar};
use ferveo::bls::Keypair;
use ferveo::hybridvss_sh::*;
use ferveo::hybridvss_rec;
use rand::Rng;

// Fixed seed for reproducability
fn rng() -> rand::rngs::StdRng {
    use rand::SeedableRng;
    rand::rngs::StdRng::seed_from_u64(0)
}

fn random_scalar<R: Rng>(rng: &mut R) -> Scalar {
    <Scalar as ff::Field>::random(rng)
}

// A HybridVss_sh scheme
struct Scheme {
    d: u32, // the dealer index
    nodes: Vec<Context>,
    p: Vec<G1Affine>, // public keys
    tau: u32, // session identifier
}

impl Scheme {
    /* Generate a fresh setup with `n` participants,
    failure threshold `f`,
    threshold `t` */
    fn init<R: Rng>(n: u32, f: u32, t: u32, rng: &mut R) -> Self {
        let mut keypairs: Vec<Keypair> =
            (0..n).map(|_| random_scalar(rng).into()).collect();
        // sort keypairs by cpk
        keypairs.sort();
        let (secrets, pubkeys): (Vec<_>, Vec<_>) =
            keypairs.iter().map(|kp| (kp.secret, kp.pubkey)).unzip();
        let d: u32 = rng.gen_range(0, n);
        let tau: u32 = rng.gen();
        let nodes = (0..n)
            .map(|i| Context::init(d, f, i, &pubkeys, t, tau))
            .collect();
        Scheme { d, nodes, p:pubkeys, tau }
    }
}

#[test]
// test that all nodes echo with a valid send
fn send_echo_valid() {
    let mut rng = rng();
    let scheme = Scheme::init(6, 0, 4, &mut rng);
    let share = Share {
        s: random_scalar(&mut rng),
    };
    let mut nodes = scheme.nodes;
    let sends = nodes[scheme.d as usize].share(&mut rng, share);
    let mut responses: Vec<Option<_>> = nodes
        .iter_mut()
        .zip(sends)
        .map(|(node, send)| node.send(send))
        .collect();
    assert!(responses.iter_mut().all(|resp| resp.is_some()))
}

#[test]
// test that all nodes do not echo with an invalid send
fn send_echo_invalid() {
    let mut rng = rng();
    let scheme = Scheme::init(6, 0, 4, &mut rng);
    let share = Share {
        s: random_scalar(&mut rng),
    };
    let mut nodes = scheme.nodes;

    let mut sends = nodes[scheme.d as usize].share(&mut rng, share);
    /* Reverse the sends to make them all invalid.
       nb. this only works for an even, positive number of sends */
    sends.reverse();
    let mut responses: Vec<Option<_>> = nodes
        .iter_mut()
        .zip(sends)
        .map(|(node, send)| node.send(send))
        .collect();
    assert!(responses.iter_mut().all(|resp| resp.is_none()))
}

#[test]
// test that all nodes generate ready messages with enough valid echos
fn echo_ready_threshold() {
    let mut rng = rng();
    let scheme = Scheme::init(8, 0, 5, &mut rng);
    let share = Share {
        s: random_scalar(&mut rng),
    };
    let mut nodes = scheme.nodes;
    let sends = nodes[scheme.d as usize].share(&mut rng, share);
    let echos: Vec<Vec<Echo>> = nodes
        .iter_mut()
        .zip(sends)
        .map(|(node, send)| node.send(send).unwrap())
        .collect();
    for (i, node) in nodes.iter_mut().enumerate() {
        use rand::seq::IteratorRandom;
        // pairs of node indexes m and echos for node index i
        let echos_mi = echos.iter().map(|es| es[i].clone()).enumerate();
        // accept echos from all nodes, in random order
        echos_mi.choose_multiple(&mut rng, 8)
            .into_iter()
            .enumerate()
            .for_each(|(count, (m, echo))| {
                let echo_response = node.echo(m as u32, echo);
                if count == 7 - 1 {
                    assert!(echo_response.is_some())
                } else {
                    assert!(echo_response.is_none())
                }
            })
    }
}

#[test]
// test that all nodes finish given enough ready messages
fn ready_shared_threshold() {
    let mut rng = rng();
    let scheme = Scheme::init(8, 0, 5, &mut rng);
    let share = Share {
        s: random_scalar(&mut rng),
    };
    let mut nodes = scheme.nodes;
    let sends = nodes[scheme.d as usize].share(&mut rng, share);
    let echos: Vec<Vec<Echo>> = nodes
        .iter_mut()
        .zip(sends)
        .map(|(node, send)| node.send(send).unwrap())
        .collect();
    // generate ready messages based on a random selection of echos
    let ready_messages: Vec<_> =
        nodes.iter_mut().enumerate().map(|(i, node)| {
            use rand::seq::IteratorRandom;
            let mut res = None;
            echos.iter()
                .map(|es| es[i].clone())
                .enumerate()
                .choose_multiple(&mut rng, 7)
                .into_iter()
                .for_each(|(m, echo)| res = node.echo(m as u32, echo));
            res.expect("Unexpected failure to generate ready message")
        }).collect();
    nodes.iter_mut().enumerate().for_each(|(i, node)| {
        use rand::seq::IteratorRandom;
        let mut res = None;
        ready_messages.iter()
            .map(|rs| rs[i].clone())
            .enumerate()
            .choose_multiple(&mut rng, 8-5-0)
            .into_iter()
            .for_each(|(m, ready)| {
                assert!(res.is_none());
                res = node.ready(m as u32, ready);
            });
        assert!(res.is_some());
        assert!(res.unwrap().is_right())
    })
}

#[test]
// test share reconstruction
fn reconstruct_share() {
    use rand::seq::IteratorRandom;
    let mut rng = rng();
    let scheme = Scheme::init(8, 0, 5, &mut rng);
    let s = random_scalar(&mut rng);
    let share = Share {
        s: s.clone(),
    };
    let mut nodes = scheme.nodes;
    let sends = nodes[scheme.d as usize].share(&mut rng, share);
    let echos: Vec<Vec<Echo>> = nodes
        .iter_mut()
        .zip(sends)
        .map(|(node, send)| node.send(send).unwrap())
        .collect();
    // generate ready messages based on a random selection of echos
    let ready_messages: Vec<_> =
        nodes.iter_mut().enumerate().map(|(i, node)| {
            use rand::seq::IteratorRandom;
            let mut res = None;
            echos.iter()
                .map(|es| es[i].clone())
                .enumerate()
                .choose_multiple(&mut rng, 7)
                .into_iter()
                .for_each(|(m, echo)| res = node.echo(m as u32, echo));
            res.expect("Unexpected failure to generate ready message")
        }).collect();
    // generate shared messages based on a random selection of ready messages
    let shared_messages: Vec<_> =
        nodes.iter_mut().enumerate().map(|(i, node)| {
            let mut res = None;
            ready_messages.iter()
                .map(|rs| rs[i].clone())
                .enumerate()
                .choose_multiple(&mut rng, 8-5-0)
                .into_iter()
                .for_each(|(m, ready)| {
                    assert!(res.is_none());
                    res = node.ready(m as u32, ready);
                });
            res.expect("Unexpected failure to generate ready message")
               .expect_right("Unexpected failure to generate ready message")
        }).collect();
    // Initialize a rec protocol node
    let i = rng.gen_range(0, 8);
    let mut rec_node = {
        let C = (*shared_messages[i as usize].C).clone();
        let s = shared_messages[i as usize].s;
        let tau = scheme.tau;
        hybridvss_rec::Context::init(C, scheme.d, i, &scheme.p, s, 5, tau)
    };
    // accept T + 1 shares
    let mut z_i = None;
    shared_messages.into_iter().enumerate()
        .choose_multiple(&mut rng, 5+1)
        .into_iter()
        .for_each(|(j, shared_message)| {
            assert!(z_i.is_none());
            z_i = rec_node.reconstruct_share(j as u32, shared_message.s);
        });
    let z_i = z_i.expect("failed to reconstruct share");
    assert!(z_i == s);
}
