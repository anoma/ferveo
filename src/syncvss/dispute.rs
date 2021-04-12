#![allow(unused_imports)]

use crate::dkg;

pub fn send_dispute(dkg: &mut dkg::Context) {}

pub fn recv_dispute(dkg: &mut dkg::Context, dispute: Vec<u8>) {}
