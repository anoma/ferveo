pub use ark_bls12_381::Bls12_381 as EllipticCurve;
use criterion::{criterion_group, criterion_main, Criterion};
use ferveo_common::{ValidatorSet, TendermintValidator};
use pprof::criterion::{Output, PProfProfiler};

use ferveo::*;

pub fn dkgs(c: &mut Criterion) {
    // use a fixed seed for reproducability
    use rand::SeedableRng;
    let _rng = rand::rngs::StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("compare DKGs with 8192 shares");
    group.sample_size(10);

    //Benchmarking compare DKGs with 8192 shares/Pedersen Pallas: Collecting 10 sample                                                                                compare DKGs with 8192 shares/Pedersen Pallas
    //time:   [95.895 s 97.154 s 98.507 s]
    /*group.bench_function("Pedersen Pallas", |b| {
        b.iter(|| pedersen::<ark_pallas::Affine>())
    });
    group.measurement_time(core::time::Duration::new(30, 0));*/
    // Benchmarking compare DKGs with 8192 shares/Pedersen BLS12-381: Collecting 10 sam                                                                                compare DKGs with 8192 shares/Pedersen BLS12-381
    //time:   [177.12 s 178.73 s 180.47 s]
    /*group.bench_function("Pedersen BLS12-381", |b| {
        b.iter(|| pedersen::<ark_bls12_381::G1Affine>())
    });*/
    // 2130.7 seconds per iteration to verify pairwise
    group.measurement_time(core::time::Duration::new(60, 0));
    group.bench_function("PVDKG BLS12-381", |b| b.iter(|| setup_dealt_dkg(10)));
}

criterion_group! {
    name = pvdkg_bls;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = dkgs
}

criterion_main!(pvdkg_bls);

/// Generate a set of keypairs for each validator
pub fn gen_keypairs(num: u64) -> Vec<ferveo_common::Keypair<EllipticCurve>> {
    let rng = &mut ark_std::test_rng();
    (0..num)
        .map(|_| ferveo_common::Keypair::<EllipticCurve>::new(rng))
        .collect()
}

/// Generate a few validators
pub fn gen_validators(keypairs: &[ferveo_common::Keypair<EllipticCurve>]) -> ValidatorSet<EllipticCurve> {
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
) -> PubliclyVerifiableDkg<EllipticCurve> {
    let keypairs = gen_keypairs(num);
    let validators = gen_validators(&keypairs);
    let me = validators.validators[validator].clone();
    PubliclyVerifiableDkg::new(
        validators,
        Params {
            tau: 0,
            security_threshold: 300 / 3,
            total_weight: 300,
            retry_after: 2,
        },
        me,
        keypairs[validator].clone(),
    )
    .expect("Setup failed")
}

/// Set up a dkg with enough pvss transcripts to meet the threshold
pub fn setup_dealt_dkg(num: u64) {
    let rng = &mut ark_std::test_rng();
    // gather everyone's transcripts
    let mut transcripts = vec![];
    for i in 0..num {
        let mut dkg = setup_dkg(i as usize, num);
        transcripts.push(dkg.share(rng).expect("Test failed"));
    }
    // our test dkg
    let mut dkg = setup_dkg(0, num);
    // iterate over transcripts from lowest weight to highest
    for (sender, pvss) in transcripts.into_iter().rev().enumerate() {
        dkg.apply_message(
            dkg.validators[num as usize - 1 - sender].validator.clone(),
            pvss,
        )
        .expect("Setup failed");
    }
}
