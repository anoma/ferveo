use crate::dkg::*;

/*#[derive(Clone, Debug)]
pub struct ParticipantBuilder<E: Engine> {
    pub ed_key: ed25519::PublicKey,
    pub session_key: E::SessionKey,
    pub stake: u64,
}*/

pub trait Announcement {
    type Participant;
    fn stake(&self) -> u64;
    fn participant(
        &self,
        weight: u32,
        share_range: std::ops::Range<usize>,
    ) -> Self::Participant;
}
/*
pub trait Participant {
    fn new<S>(ed_key: ed25519::PublicKey,
        session_key: S,
        weight: u32,
        share_range: std::ops::Range<usize>) -> Self;
}*/
