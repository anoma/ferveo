#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]
#![allow(unused_imports)]

//use ark_poly_commit::kzg10::{Powers, VerifierKey};

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
use serde::*;

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
pub enum DKGState<E: ark_ec::PairingEngine> {
    Init {
        announce_messages: Vec<PubliclyVerifiableAnnouncement<E>>,
    },
    Sharing {
        finalized_weight: u32,
    },
    Success,
    Failure,
}
