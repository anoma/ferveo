/*
Randomness beacon from BLS threshold signatures.
 */

// import the bls.rs stuff
// create a struct and impl functions for rounds
// test the generation of random stuffs

use crate::bls::{sign_g2, Setup};
use bls12_381::{G2Affine, Scalar};
use sha2::{Digest, Sha256};

pub struct PartialRand {
    pub value: G2Affine,
    pub round: usize,
    pub random_beacon: G2Affine,
}

impl PartialRand {
    fn init(msg: &[u8], secret_share: Scalar) -> Self {
        PartialRand {
            value: sign_g2(secret_share, msg),
            round: 0,
            random_beacon: G2Affine::identity(),
        }
    }

    fn update_share(&mut self, secret_share: Scalar) {
        assert!(self.random_beacon != G2Affine::identity());
        let catsig: Vec<u8> = [
            &[self.round as u8][..],
            &self.random_beacon.to_compressed()[..],
        ]
        .concat();
        let s = String::from_utf8_lossy(&catsig);
        let mut hasher = Sha256::new();
        hasher.update(&*s);
        let res = hasher.finalize();
        let tmp = String::from_utf8_lossy(&res);
        let msg = tmp.as_bytes();
        // update self
        self.value = sign_g2(secret_share, msg);
        self.round += 1;
    }

    fn init_random_beacon(
        msg: &[u8],
        partial_rands: &mut [PartialRand],
        positions: &[usize],
        setup: &Setup,
    ) -> G2Affine {
        let partial_sigs: Vec<G2Affine> =
            partial_rands.iter().map(|pr| pr.value).collect();
        assert!(setup.verify_partial_sigs(&partial_sigs, &positions, msg));
        let random_beacon =
            setup.build_group_signature(&partial_sigs, &positions);
        for pr in partial_rands.iter_mut() {
            pr.random_beacon = random_beacon;
        }
        random_beacon
    }

    fn random_beacon(
        previous_random_beacon: G2Affine,
        partial_rands: &[PartialRand],
        positions: &[usize],
        setup: &Setup,
    ) -> G2Affine {
        let catsig: Vec<u8> = [
            &[(partial_rands[0].round - 1) as u8][..],
            &previous_random_beacon.to_compressed()[..],
        ]
        .concat();
        let mut hasher = Sha256::new();
        let s = String::from_utf8_lossy(&catsig);
        hasher.update(&*s);
        let res = hasher.finalize();
        let tmp = String::from_utf8_lossy(&res);
        let msg = tmp.as_bytes();

        let partial_sigs: Vec<G2Affine> =
            partial_rands.iter().map(|pr| pr.value).collect();

        assert!(setup.verify_partial_sigs(&partial_sigs, &positions, msg));
        setup.build_group_signature(&partial_sigs, &positions)
    }

    fn update_random_beacon(&mut self, new_random_beacon: G2Affine) {
        self.random_beacon = new_random_beacon;
    }
}

#[test]
pub fn test_rand_beacon() {
    use crate::bls::{eval, pubkey, random_scalar, verify_g2, Setup};
    use rand::{seq::IteratorRandom, thread_rng, SeedableRng};

    // Fixed seed for reproducability
    fn rng() -> rand::rngs::StdRng {
        rand::rngs::StdRng::seed_from_u64(0)
    }
    let mut rng = rng();

    // secret sharing setup
    let n = 10;
    let t = 8;

    let mut rng_scalar = thread_rng();
    let poly: Vec<Scalar> =
        (0..t).map(|_| random_scalar(&mut rng_scalar)).collect();
    let group_secret = eval(&poly, Scalar::zero());
    let group_pk = pubkey(&group_secret);

    let secret_shares: Vec<Scalar> = (0..n)
        .map(|i| eval(&poly, Scalar::from(i as u32)))
        .collect();
    let pks: Vec<_> = secret_shares.iter().map(|s| pubkey(&s)).collect();

    let setup = Setup {
        pubkeys: pks.clone(),
        group_pubkey: group_pk.clone(),
    };

    // round 0
    let msg: &[u8; 64] =
        b"0314159265314159265314159265314159265314159265314159265314159265";
    let mut positions = (0..n).choose_multiple(&mut rng, t);
    positions.sort();

    let mut partial_rands: Vec<PartialRand> = positions
        .iter()
        .map(|i| PartialRand::init(msg, secret_shares[*i]))
        .collect();

    let rand_beac_0 = PartialRand::init_random_beacon(
        msg,
        &mut partial_rands,
        &positions,
        &setup,
    );

    assert!(verify_g2(&group_pk, &rand_beac_0, msg));

    let rounds = 6;
    let mut rands: Vec<_> = vec![G2Affine::identity(); rounds + 1];
    rands[0] = rand_beac_0;

    for round in 1..rounds {
        positions = (0..n).choose_multiple(&mut rng, t);
        positions.sort();
        for (i, j) in positions.iter().enumerate() {
            partial_rands[i].update_share(secret_shares[*j])
        }
        rands[round] = PartialRand::random_beacon(
            rands[round - 1],
            &partial_rands,
            &positions,
            &setup,
        );
        for i in 0..t {
            partial_rands[i].update_random_beacon(rands[round]);
        }
    }
    // we need to recompute the messages in order to do a
    // verification...
    // msgs = (...)
    // rands.iter().zip(msgs.iter()).map(
    // 	|(rand,msg)|
    // 	assert!(verify_g2(&group_pk,
    // 			  &rand, msg)));
}
