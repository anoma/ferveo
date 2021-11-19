#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]
#![allow(unused_imports)]

use crate::*;
use anyhow::anyhow;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::Zero;
use ark_ff::{Field, One};
use ark_poly::{
    polynomial::univariate::DensePolynomial, polynomial::UVPolynomial,
    EvaluationDomain, Polynomial,
};
use ed25519_dalek as ed25519;

pub mod common;
pub mod pv;
pub use common::*;
pub use pv::*;

// DKG parameters
#[derive(Copy, Clone, Debug)]
pub struct Params {
    pub tau: u64,
    pub security_threshold: u32, // threshold
    pub total_weight: u32,       // total weight
}

#[derive(Debug, Clone)]
pub enum DkgState<E: PairingEngine> {
    Init {announced: u32},
    Shared { accumulated_weight: u32 },
    Dealt,
    Success { final_key: E::G1Affine},
    Invalid,
}
