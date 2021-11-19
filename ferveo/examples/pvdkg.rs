pub use ark_bls12_381::Bls12_381 as EllipticCurve;
use ferveo::*;
use ferveo_common::Validator;

pub fn main() {
    setup_dealt_dkg(10);
}


/// Generate a few validators
pub fn gen_validators(num: u64) -> ValidatorSet {
    ValidatorSet::new(
        (0..num)
            .map(|i| TendermintValidator {
                power: i,
                address: format!("validator_{}", i),
            })
            .collect(),
    )

}

/// Create a test dkg in state [`DkgState::Init`]
pub fn setup_dkg(
    validator: usize,
    num: u64,
) -> PubliclyVerifiableDkg<EllipticCurve> {
    let rng = &mut ark_std::test_rng();
    let validators = gen_validators(num);
    let me = validators.validators[validator].clone();
    PubliclyVerifiableDkg::new(
        validators,
        Params {
            tau: 0,
            security_threshold: 300 / 3,
            total_weight: 300,
        },
        me,
        rng,
    )
    .expect("Setup failed")
}

/// Setup a dkg instance with all announcements received
pub fn setup_shared_dkg(
    validator: usize,
    num: u64,
) -> PubliclyVerifiableDkg<EllipticCurve> {
    let rng = &mut ark_std::test_rng();
    let mut dkg = setup_dkg(validator, num);
  
    // generated the announcements for all other validators
    for i in 0..num {
        if i as usize == validator {
            continue;
        }
        let announce = Message::Announce(
            ferveo_common::Keypair::<EllipticCurve>::new(rng).public(),
        );
        let sender = dkg.validator_set.validators[i as usize].clone();
        dkg.verify_message(&sender, &announce, rng)
            .expect("Setup failed");
        dkg.apply_message(sender, announce).expect("Setup failed");
    }
    dkg
}

/// Set up a dkg with enough pvss transcripts to meet the threshold
pub fn setup_dealt_dkg(num: u64) {
    let rng = &mut ark_std::test_rng();
    // gather everyone's transcripts
    let mut transcripts = vec![];
    for i in 0..num {
        let mut dkg = setup_shared_dkg(i as usize, num);
        transcripts.push(dkg.share(rng).expect("Test failed"));
    }
    // our test dkg
    let mut dkg = setup_shared_dkg(0, num);
    // iterate over transcripts from lowest weight to highest
    for (sender, pvss) in transcripts.into_iter().rev().enumerate() {
        dkg.apply_message(
            dkg.validator_set.validators[num as usize - 1 - sender].clone(),
            pvss,
        )
        .expect("Setup failed");
    }
}
