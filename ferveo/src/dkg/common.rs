use crate::*;
use ferveo_common::ValidatorPublicKey;
use itertools::izip;

/// partition_domain takes as input a vector of validators from
/// participants in the DKG, containing their total stake amounts
/// and public address (as Bech32m string)
///
/// The validators are *assumed to be* stable-sorted by staking weight
/// (so highest weight participants come first), then by address
/// and the DKG share domain is partitioned into continuous segments roughly
/// the same relative size as the staked weight.
///
/// partition_domain returns a vector of DKG participants
pub fn partition_domain<E: PairingEngine>(
    params: &Params,
    validator_set: &ValidatorSet,
) -> Result<Vec<ferveo_common::Validator<E>>> {
    // Sort participants from greatest to least stake

    // Compute the total amount staked
    let total_voting_power =
        params.total_weight as f64 / validator_set.total_voting_power() as f64;

    // Compute the weight of each participant rounded down
    let mut weights = validator_set
        .validators
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

    let mut allocated_weight = 0usize;
    let mut participants = vec![];
    for weight in &weights {
        participants.push(ferveo_common::Validator::<E> {
            key: ValidatorPublicKey::Unannounced,
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
