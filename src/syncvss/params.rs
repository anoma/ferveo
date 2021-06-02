#![allow(unused_imports)]

use rand::Rng;

use crate::{Affine, Scalar};
//type Scalar = Fr;
use ark_poly::{
    polynomial::univariate::DensePolynomial, polynomial::UVPolynomial,
    EvaluationDomain, Polynomial, Radix2EvaluationDomain,
};

// VSS parameters
#[derive(Copy, Clone)]
pub struct Params {
    pub d: u32,            // dealer index
    pub f: u32,            // failure threshold
    pub t: u32,            // threshold
    pub total_weight: u32, // total weight of all shares
}

impl Params {
    // initialize with random values for `d`
    pub fn random_dealer<R: Rng>(
        f: u32,
        t: u32,
        total_weight: u32,
        rng: &mut R,
    ) -> Self {
        let d = rng.gen_range(0, 10);
        Params {
            d,
            f,
            t,
            total_weight,
        }
    }
}
