use bls12_381::{G2Affine, G2Projective, Scalar};
use ferveo::bls::*;

// Fixed seed for reproducability
fn rng() -> rand::rngs::StdRng {
    use rand::SeedableRng;
    rand::rngs::StdRng::seed_from_u64(0)
}

// A threshold scheme with n participants
struct Scheme {
    memkeys: Vec<G2Affine>,
    n: usize,
    rng: rand::rngs::StdRng,
    secrets: Vec<Scalar>,
    setup: Setup,
}

// Generate a fresh setup with `n` participants and compute membership keys
fn scheme(n: usize) -> Scheme {
    let mut rng = rng();
    let mut keypairs: Vec<Keypair> = (0..n)
        .map(|_| <Scalar as ff::Field>::random(&mut rng).into())
        .collect();
    // sort keypairs by cpk
    keypairs.sort();
    let (secrets, pubkeys): (Vec<_>, Vec<_>) =
        keypairs.iter().map(|kp| (kp.secret, kp.pubkey)).unzip();
    let setup: Setup = pubkeys.into_iter().collect();
    let mk_frags: Vec<Vec<_>> = keypairs
        .into_iter()
        .map(|kp| setup.memkey_frags(&kp))
        .collect();
    // generate the `i`th memkey
    let memkey = |i: usize| {
        let frags: Vec<_> = mk_frags.iter().map(|cs| cs[i]).collect();
        setup.memkey(i, &frags)
    };

    let memkeys: Vec<_> = (0..n).map(memkey).map(Option::unwrap).collect();

    Scheme {
        memkeys,
        n,
        rng,
        secrets,
        setup,
    }
}

impl Scheme {
    // Sign a message with secrets at the given positions and aggregate.
    fn sign(&self, positions: &[usize], msg: &[u8]) -> G2Affine {
        let mut positions = positions.to_vec();
        positions.sort();
        positions.dedup();
        // sign with the secret and memkey at position `pos`
        let sigs = positions.iter().map(|pos| {
            let secret = self.secrets[*pos];
            let memkey = self.memkeys[*pos];
            sign_with_mk_g2(secret, memkey, &self.setup.prefix_apk(msg))
        });
        let sig = sigs.map(G2Projective::from).sum::<G2Projective>().into();
        sig
    }

    /* Sign a message with `m` signatures and aggregate,
    also returning positions used.
    Positions are chosen randomly.
    Panics if `m < self.n` */
    fn sign_random_positions(
        &mut self,
        m: usize,
        msg: &[u8],
    ) -> (G2Affine, Vec<usize>) {
        use rand::seq::IteratorRandom;
        assert!(m <= self.n);
        let mut positions = (0..self.n).choose_multiple(&mut self.rng, m);
        positions.sort();
        (self.sign(&positions, msg), positions)
    }

    /* Verify an aggregate threshold signature `sig` on `msg`,
       with threshold `m`, and participant `positions`.
    */
    fn verify_threshold(
        &self,
        m: usize,
        sig: &G2Affine,
        positions: &[usize],
        msg: &[u8],
    ) -> bool {
        self.setup.verify_threshold(m, sig, positions, msg)
    }
}

#[test]
// Sign and verify messages according to the enumerated m-of-n schemes
fn sign_verify() {
    // all possible schemes from 0-of-0 to 9-of-9
    let schemes = (0..=9).flat_map(|n| (0..=n).map(move |m| (m, n)));
    let msg: &[u8] = b"Lorem ipsum, dolor sit amet";
    let test_scheme = |(m, n)| {
        let mut scheme = scheme(n);
        let (sig, positions) = scheme.sign_random_positions(m, msg);
        assert!(
            scheme.verify_threshold(m, &sig, &positions, msg),
            "scheme failed: {}-of-{} with positions {:?}",
            m,
            n,
            positions
        )
    };
    schemes.for_each(test_scheme)
}
