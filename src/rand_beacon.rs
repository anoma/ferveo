/*
Randomness beacon from BLS threshold signatures.
 */

// import the bls.rs stuff
// create a struct and impl functions for rounds
// test the generation of random stuffs

use crate::bls::*;
use bls12_381::{G1Affine, Scalar};
use rand::{seq::IteratorRandom, thread_rng, Rng, SeedableRng};

pub struct RandBeacon {
    pub round: usize,
    pub value: G1Affine,
}

impl RandBeacon {
    // functions here!
}

#[test]
pub fn test_rand_beacon() {
    // Fixed seed for reproducability
    fn rng() -> rand::rngs::StdRng {
        rand::rngs::StdRng::seed_from_u64(0)
    }
    let mut rng = rng();
    assert!(true);
}
