use bls12_381::{G2Affine, G2Projective, Scalar};
use ferveo::bls::Keypair;
use ferveo::hybridvss_sh::*;
use rand::Rng;

// Fixed seed for reproducability
fn rng() -> rand::rngs::StdRng {
    use rand::SeedableRng;
    rand::rngs::StdRng::seed_from_u64(0)
}

fn random_scalar<R: Rng>(rng: &mut R) -> Scalar {
    <Scalar as ff::Field>::random(rng)
}

// A HybridVss scheme
struct Scheme {
    d: u32, // the dealer index
    nodes: Vec<Context>,
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
        Scheme { d, nodes }
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
