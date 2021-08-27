use crate::*;

/// partition_domain takes as input a vector of Announcement messages from
/// participants in the DKG, containing their total stake amounts
/// and their ephemeral encryption key
///
/// The Announcement messages are stable-sorted by staking weight
/// (so highest weight participants come first, then by announcement order)
/// and the DKG share domain is partitioned into continuous segments roughly
/// the same relative size as the staked weight.
///
/// partition_domain returns a vector of DKG participants
pub fn partition_domain<E>(
    params: &Params,
    validator_set: &tendermint::validator::Set,
    //announce_messages: &mut Vec<PubliclyVerifiableAnnouncement<E>>,
) -> Result<Vec<PubliclyVerifiableParticipant<E>>>
where
    E: ark_ec::PairingEngine,
{
    let validators = validator_set.validators();
    // Sort participants from greatest to least stake

    // Compute the total amount staked
    let total_stake = params.total_weight as f64
        / validator_set.total_voting_power().value() as f64;

    // Compute the weight of each participant rounded down
    let mut weights = validators
        .iter()
        .map(|p| (p.power() as f64 * total_stake).floor() as u32)
        .collect::<Vec<_>>();

    // Add any excess weight to the largest weight participants
    let adjust_weight = params
        .total_weight
        .checked_sub(weights.iter().sum())
        .ok_or_else(|| anyhow!("adjusted weight negative"))?
        as usize;
    for i in &mut weights[0..adjust_weight] {
        *i += 1;
    }

    // total_weight is allocated among all participants
    assert_eq!(weights.iter().sum::<u32>(), params.total_weight);

    let mut allocated_weight = 0usize;
    let mut participants = vec![];
    for (announcement, weight) in validators.iter().zip(weights) {
        let share_range = allocated_weight..allocated_weight + weight as usize;

        participants.push(PubliclyVerifiableParticipant::<E> {
            //ed_key: announcement.signer,
            session_key: announcement.session_key,
            weight,
            share_range,
        });
        allocated_weight = allocated_weight
            .checked_add(weight as usize)
            .ok_or_else(|| anyhow!("allocated weight overflow"))?;
    }
    Ok(participants)
}
