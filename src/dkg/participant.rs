use crate::dkg::*;

#[derive(Clone, Debug)]
pub struct ParticipantBuilder<E: Engine> {
    pub ed_key: ed25519::PublicKey,
    pub session_key: E::SessionKey,
    pub stake: u64,
}

#[derive(Clone, Debug)]
pub struct Participant<E: Engine> {
    pub ed_key: ed25519::PublicKey,
    pub session_key: E::SessionKey,
    pub weight: u32,
    pub share_range: std::ops::Range<usize>,
}
