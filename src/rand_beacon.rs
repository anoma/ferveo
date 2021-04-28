/*
Randomness beacon from BLS threshold signatures.
 */

// import the bls.rs stuff
// create a struct and impl functions for rounds
// test the generation of random stuffs

use crate::bls::{sign_g2, verify_g2, Setup, random_scalar, eval, pubkey};
use bls12_381::{G2Affine, Scalar};
use rand::{seq::IteratorRandom, thread_rng, Rng, SeedableRng};
use sha2::{Sha256, Digest};

// pub struct PartialRand {
//     pub value: G2Affine,
//     pub round: usize,
//     pub previous: RandBeacon,
// }

/*

Init : a random value...

Round: 
 each particicpant generate their partial sig sigma_i from sigma_{i-1},
 i and their secret.
 once there is enough sigma_i's, the randbeac is the signature from
 the partial sigs.

*/

// impl PartialRand {
//     pub fn compute(&self, secret_share: Scalar) {
// 	//TODO NOT WORKING
// 	let msg = b"abc";//: &[u8] = [
// 	    //self.round.to_string(),
// 	    //self.previous.to_string()
// 	//].concat();
// 	self.value = sign_g2(secret_share, msg);
//     }
// }

// pub struct RandBeacon {
//     pub setup: Setup,
//     pub round: usize,
//     pub partial_states: &[G2Affine],
//     pub value: G1Affine,
// }

// impl RandBeacon {

//     pub fn compute(&self) {
// 	let sig = self.setup.compute_group_signature(self.partial_states);
	
//     }
//     // functions here!
// }

#[test]
pub fn test_rand_beacon() {
    // Fixed seed for reproducability
    fn rng() -> rand::rngs::StdRng {
        rand::rngs::StdRng::seed_from_u64(0)
    }
    let mut rng = rng();

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
    let pks: Vec<_> =
        secret_shares.iter().map(|s| pubkey(&s)).collect();

    let setup = Setup {pubkeys: pks.clone(), group_pubkey:
		       group_pk.clone()};
    
    // randomness

    // round 0
    let mut msg: &[u8] = b"314159265";
    let mut positions = (0..n).choose_multiple(&mut rng, t);
    positions.sort();
    let partial_sigma0: Vec<_> = positions.iter()
    	.map(|i| sign_g2(secret_shares[*i], msg)).collect();
    assert!(setup.verify_partial_sigs(&partial_sigma0, &positions, msg));

    let sigma0 = setup.build_group_signature(&partial_sigma0, &positions);
    assert!(verify_g2(&group_pk, &sigma0, msg));

    let rounds = 6;
    let mut rands : Vec<_> = vec![G2Affine::identity(); rounds+1];
    rands[0] = sigma0;
    
    for round in 1..rounds {
	let mut hasher = Sha256::new();
	let catsig:Vec<u8> = [
	    &[round as u8][..],
	    &sigma0.to_compressed()[..]
	].concat();
	let s = String::from_utf8_lossy(&catsig);
	hasher.update(&*s);
	let res = hasher.finalize();
	let tmp = String::from_utf8_lossy(&res);
	msg = tmp.as_bytes();
	positions = (0..n).choose_multiple(&mut rng, t);
	positions.sort();
	let partial_sigma1: Vec<_> = positions.iter()
    	    .map(|i| sign_g2(secret_shares[*i], msg)).collect();
	assert!(setup.verify_partial_sigs(&partial_sigma1, &positions, msg));
	
	let sigma = setup.build_group_signature(&partial_sigma1,
						 &positions);
	rands[round] = sigma;
	// assert!(verify_g2(&group_pk, &sigma, msg));
    }
}
