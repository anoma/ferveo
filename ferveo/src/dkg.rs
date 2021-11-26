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
use ark_serialize::*;
use ed25519_dalek as ed25519;

pub mod common;
pub mod pv;
pub use common::*;
pub use pv::*;

// DKG parameters
#[derive(Copy, Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Params {
    pub tau: u64,
    pub security_threshold: u32, // threshold
    pub total_weight: u32,       // total weight
}

#[derive(Debug, Clone)]
pub enum DkgState<E: PairingEngine> {
    Init { announced: u32 },
    Shared { accumulated_weight: u32 },
    Dealt,
    Success { final_key: E::G1Affine },
    Invalid,
}

impl<E: PairingEngine> CanonicalSerialize for DkgState<E> {
    #[inline]
    fn serialize<W: Write>(
        &self,
        mut writer: W,
    ) -> Result<(), SerializationError> {
        match self {
            Self::Init { announced } => {
                CanonicalSerialize::serialize(&0u8, &mut writer)?;
                CanonicalSerialize::serialize(announced, &mut writer)
            }
            Self::Shared { accumulated_weight } => {
                CanonicalSerialize::serialize(&1u8, &mut writer)?;
                CanonicalSerialize::serialize(accumulated_weight, &mut writer)
            }
            Self::Dealt => CanonicalSerialize::serialize(&2u8, &mut writer),
            Self::Success { final_key } => {
                CanonicalSerialize::serialize(&3u8, &mut writer)?;
                final_key.serialize(&mut writer)
            }
            Self::Invalid => CanonicalSerialize::serialize(&4u8, &mut writer),
        }
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        match self {
            Self::Init { announced } => {
                0u8.serialized_size() + announced.serialized_size()
            }
            Self::Shared { accumulated_weight } => {
                1u8.serialized_size() + accumulated_weight.serialized_size()
            }
            Self::Dealt => 2u8.serialized_size(),
            Self::Success { final_key } => {
                3u8.serialized_size() + final_key.serialized_size()
            }
            Self::Invalid => 4u8.serialized_size(),
        }
    }
}

impl<E: PairingEngine> CanonicalDeserialize for DkgState<E> {
    #[inline]
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let variant = <u8 as CanonicalDeserialize>::deserialize(&mut reader)?;
        match variant {
            0 => Ok(Self::Init {
                announced: <u32 as CanonicalDeserialize>::deserialize(
                    &mut reader,
                )?,
            }),
            1 => Ok(Self::Shared {
                accumulated_weight: <u32 as CanonicalDeserialize>::deserialize(
                    &mut reader,
                )?,
            }),
            2 => Ok(Self::Dealt),
            3 => Ok(Self::Success {
                final_key: <E as PairingEngine>::G1Affine::deserialize(
                    &mut reader,
                )?,
            }),
            4 => Ok(Self::Invalid),
            _ => Err(SerializationError::InvalidData),
        }
    }
}
