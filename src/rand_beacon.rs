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
    pub random_beacon: RandomBeacon,
}

impl PartialRand {
    fn init(seed: &[u8], secret_share: Scalar) -> Self {
	/*
	 * Initialize a PartialRand using a fixed seed
	 */
        PartialRand {
            value: sign_g2(secret_share, seed),
            round: 0,
            random_beacon: RandomBeacon {
		value: G2Affine::identity(),
		prev_value: G2Affine::identity(),
		round: 0,
	    },
        }
    }

    fn update_share(&mut self, secret_share: Scalar) {
	/*
	 * update the value of a PartialRand by signing the message
	 * H(r|| previous random beacon).
	 */
        assert!(self.random_beacon.value != G2Affine::identity());
        let catsig: Vec<u8> = [
            &[self.round as u8][..],
            &self.random_beacon.value.to_compressed()[..],
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

    fn update_rb(&mut self, rb: RandomBeacon) {
	/*
	 * Update the random beacon value of a PartialRand.
	 */
	self.random_beacon = rb;
    }
    
}

#[derive(Copy, Clone)]
pub struct RandomBeacon {
    pub value: G2Affine,
    pub prev_value: G2Affine,
    pub round: usize,
}

impl RandomBeacon {

    fn init(
	seed: & [u8],
	partial_rands: &mut [PartialRand],
        positions: &[usize],
        setup: &Setup,
    ) -> Self {
	/*
	 * Initialize a RandomBeacon from a list of PartialRand.
	 */
	
	// verification of the partial_sigs
	let partial_sigs: Vec<G2Affine> =
            partial_rands.iter().map(|pr| pr.value).collect();
        assert!(setup.verify_partial_sigs(&partial_sigs, &positions, seed));

	// value of the random_beacon
	let val = setup.build_group_signature(&partial_sigs, &positions);

	// update of the partial_rands.random_beacon value
	for pr in partial_rands.iter_mut() {
            pr.random_beacon.value = val;
        }

	RandomBeacon {
	    value: val,
	    prev_value: val,
	    round: 0,
	}
    }

    fn update(
    	&mut self,
        partial_rands: &mut [PartialRand],
        positions: &[usize],
        setup: &Setup,
    ) {
	/*
	 * Update the value of a RandomBeacon from a list of
	 * PartialRand.
	 */
	let saved_value = self.value;
        let catsig: Vec<u8> = [
            &[(partial_rands[0].round - 1) as u8][..],
            &self.value.to_compressed()[..],
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
        self.value = setup.build_group_signature(&partial_sigs,
						 &positions);
	self.prev_value = saved_value;
	self.round += 1;

	for pr in partial_rands {
	    pr.update_rb(*self);
	}
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
    let seed: &[u8; 64] =
        b"0314159265314159265314159265314159265314159265314159265314159265";
    let mut positions = (0..n).choose_multiple(&mut rng, t);
    positions.sort();

    let mut partial_rands: Vec<PartialRand> = positions
        .iter()
        .map(|i| PartialRand::init(seed, secret_shares[*i]))
        .collect();

    let mut rand_beac_0 = RandomBeacon::init(
    	seed,
    	&mut partial_rands,
    	&positions,
    	&setup,
    );
    
    assert!(verify_g2(&group_pk, &rand_beac_0.value, seed));

    let rounds = 5;

    for round in 1..rounds+1 {
	println!("Round {}", round);
        positions = (0..n).choose_multiple(&mut rng, t);
        positions.sort();
        for (i, j) in positions.iter().enumerate() {
            partial_rands[i].update_share(secret_shares[*j])
        }
	rand_beac_0.update(&mut partial_rands, &positions, &setup);
    }
    
    let catsig: Vec<u8> = [
        &[rounds-1 as u8][..],
	&rand_beac_0.prev_value.to_compressed()[..],
    ].concat();
    let s = String::from_utf8_lossy(&catsig);
    let mut hasher = Sha256::new();
    hasher.update(&*s);
    let res = hasher.finalize();
    let tmp = String::from_utf8_lossy(&res);
    let msg = tmp.as_bytes();

    assert!(verify_g2(&group_pk, &rand_beac_0.value, msg));
}
