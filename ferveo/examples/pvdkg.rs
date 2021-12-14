pub use ark_bls12_381::Bls12_381 as EllipticCurve;
use ferveo::*;
use ferveo_common::{TendermintValidator, ValidatorSet};
use measure_time::print_time;

pub fn main() {
    setup_dealt_dkg(10, 1024);
    setup_dealt_dkg(10, 2048);
    setup_dealt_dkg(10, 4096);
    setup_dealt_dkg(10, 8192);
}

/// Generate a set of keypairs for each validator
pub fn gen_keypairs(num: u64) -> Vec<ferveo_common::Keypair<EllipticCurve>> {
    let rng = &mut ark_std::test_rng();
    (0..num)
        .map(|_| ferveo_common::Keypair::<EllipticCurve>::new(rng))
        .collect()
}

/// Generate a few validators
pub fn gen_validators(
    keypairs: &[ferveo_common::Keypair<EllipticCurve>],
) -> ValidatorSet<EllipticCurve> {
    ValidatorSet::new(
        (0..keypairs.len())
            .map(|i| TendermintValidator {
                power: i as u64,
                address: format!("validator_{}", i),
                public_key: keypairs[i as usize].public(),
            })
            .collect(),
    )
}

/// Create a test dkg in state [`DkgState::Init`]
pub fn setup_dkg(
    validator: usize,
    num: u64,
    shares: u32,
) -> PubliclyVerifiableDkg<EllipticCurve> {
    let keypairs = gen_keypairs(num);
    let validators = gen_validators(&keypairs);
    let me = validators.validators[validator].clone();
    PubliclyVerifiableDkg::new(
        validators,
        Params {
            tau: 0,
            security_threshold: shares / 3,
            total_weight: shares,
            retry_after: 1,
        },
        me,
        keypairs[validator].clone(),
    )
    .expect("Setup failed")
}

/// Set up a dkg with enough pvss transcripts to meet the threshold
pub fn setup_dealt_dkg(num: u64, shares: u32) {
    let rng = &mut ark_std::test_rng();
    // gather everyone's transcripts
    let mut transcripts = vec![];
    for i in 0..num {
        let mut dkg = setup_dkg(i as usize, num, shares);
        transcripts.push(dkg.share(rng).expect("Test failed"));
    }
    // our test dkg
    let mut dkg = setup_dkg(0, num, shares);
    // iterate over transcripts from lowest weight to highest
    for (sender, pvss) in transcripts.into_iter().rev().enumerate() {
        if let Message::Deal(ss) = pvss.clone() {
            print_time!("PVSS verify pvdkg");
            ss.verify_full(&dkg, rng);
        }
        dkg.apply_message(
            dkg.validators[num as usize - 1 - sender].validator.clone(),
            pvss,
        )
        .expect("Setup failed");
    }
}
