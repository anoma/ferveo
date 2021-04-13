#![allow(unused_imports)]

use super::nizkp::*;
use crate::dkg;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Dispute {
    pub hash: [u8; 32],
    pub shared_secret: [u8; 4], // TODO: really a x25519_dalek::SharedSecret,
    pub nizkp: NIZKP,
}

pub fn send_dispute(dkg: &mut dkg::Context) {}

pub fn recv_dispute(dkg: &mut dkg::Context, dispute: Vec<u8>) {}
