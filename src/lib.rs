pub mod dkg;
pub mod msg;
pub mod vss;

pub use msg::ark_serde;

impl Rng for ark_std::rand::prelude::StdRng {}

pub trait Rng: ark_std::rand::CryptoRng + ark_std::rand::RngCore {}

pub mod primitives;
pub use primitives::*;

use crate::dkg::*;
use crate::msg::*;

use ark_ec::AffineCurve;
use ark_ec::ProjectiveCurve;
use ark_ff::Zero;
use ark_ff::{FftField, Field, One};
use ark_poly::{
    polynomial::univariate::DensePolynomial, polynomial::UVPolynomial,
    EvaluationDomain, Polynomial,
};
use ed25519_dalek as ed25519;
use serde::*;

use num::integer::div_ceil;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;

use anyhow::{anyhow, Result};
use chacha20poly1305::aead::Aead;
pub use dkg::*;
pub use msg::*;
pub use vss::*;

use ark_ec::msm::FixedBaseMSM;
use ark_ff::PrimeField;

use measure_time::print_time;
