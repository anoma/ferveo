use crate::*;
use itertools::izip;

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
pub fn partition_domain<E: PairingEngine>(
    params: &Params,
    validator_set: &ValidatorSet,
    validator_keys: &[ferveo_common::PublicKey<E>],
) -> Result<Vec<ferveo_common::Validator<E>>> {
    // Sort participants from greatest to least stake

    // Compute the total amount staked
    let total_voting_power = params.total_weight as f64
        / validator_set.total_voting_power() as f64;

    // Compute the weight of each participant rounded down
    let mut weights = validator_set.validators
        .iter()
        .map(|p| (p.power as f64 * total_voting_power).floor() as u32)
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
    for (_, weight, key) in
        izip!(validator_set.validators.iter(), weights.iter(), validator_keys.iter())
    {
        participants.push(ferveo_common::Validator::<E> {
            key: *key,
            weight: *weight,
            share_start: allocated_weight,
            share_end: allocated_weight + *weight as usize,
        });
        allocated_weight = allocated_weight
            .checked_add(*weight as usize)
            .ok_or_else(|| anyhow!("allocated weight overflow"))?;
    }
    Ok(participants)
}
