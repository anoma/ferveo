use crate::dkg::*;

pub trait Announcement {
    type Participant;
    fn stake(&self) -> u64;
    fn participant(
        &self,
        weight: u32,
        share_range: std::ops::Range<usize>,
    ) -> Self::Participant;
}
