#[macro_use]
extern crate criterion;

use bls12_381::{G2Affine, G2Projective, Scalar};
use criterion::Criterion;
use ferveo::bls::*;
use rand::{seq::IteratorRandom, Rng, SeedableRng};

// Fixed seed for reproducability
fn rng() -> rand::rngs::StdRng {
    rand::rngs::StdRng::seed_from_u64(0)
}

pub fn bench_single_sig_verification(c: &mut Criterion) {
    let rng = rng();
    let kp: Keypair = <Scalar as ff::Field>::random(rng).into();
    let (sk, pk) = (kp.secret, kp.pubkey);
    let msg: &[u8] = b"Lorem ipsum, dolor sit amet";
    let sig = sign_g2(sk, &msg);

    let mut group = c.benchmark_group("Signature");
    group.sample_size(10);
    group.bench_function("Single signature verification", |b| {
        b.iter(|| verify_g2(&pk, &sig, msg))
    });
    group.measurement_time(core::time::Duration::new(10, 0));
}

pub fn aggregation_setup(n: usize) -> (Vec<Scalar>, Setup) {
    let mut rng = rng();
    let mut keypairs: Vec<Keypair> = (0..n)
        .map(|_| <Scalar as ff::Field>::random(&mut rng).into())
        .collect();
    keypairs.sort();
    let (secrets, pubkeys): (Vec<_>, Vec<_>) =
        keypairs.iter().map(|kp| (kp.secret, kp.pubkey)).unzip();
    let setup: Setup = pubkeys.into_iter().collect();
    (secrets, setup)
}

pub fn threshold_setup(n: usize) -> (Vec<Scalar>, Setup, Vec<G2Affine>) {
    let mut rng = rng();
    let mut keypairs: Vec<Keypair> = (0..n)
        .map(|_| <Scalar as ff::Field>::random(&mut rng).into())
        .collect();
    keypairs.sort();
    let (secrets, pubkeys): (Vec<_>, Vec<_>) =
        keypairs.iter().map(|kp| (kp.secret, kp.pubkey)).unzip();
    let setup: Setup = pubkeys.into_iter().collect();
    let mk_frags: Vec<Vec<G2Affine>> = keypairs
        .into_iter()
        .map(|kp| setup.memkey_frags(&kp))
        .collect();
    let memkey = |i: usize| {
        let frags: Vec<_> = mk_frags.iter().map(|cs| cs[i]).collect();
        setup.memkey(i, &frags)
    };
    let memkeys = (0..n).map(memkey).map(Option::unwrap).collect();
    (secrets, setup, memkeys)
}

pub fn random_aggregated_sign(
    m: usize,
    n: usize,
    secrets: &Vec<Scalar>,
    setup: &Setup,
    msg: &[u8],
) -> (Vec<usize>, G2Affine) {
    let mut rng = rng();
    let mut positions = (0..n).choose_multiple(&mut rng, m).to_vec();
    positions.sort();
    let signatures = positions.iter().map(|i| {
	sign_g2(secrets[*i] * (*setup).coeffs[*i], &*setup.prefix_apk(msg))
    });
    (
	positions.clone(),
	signatures.map(G2Projective::from).sum::<G2Projective>().into(),
    )
}

pub fn random_threshold_sign(
    m: usize,
    n: usize,
    secrets: &Vec<Scalar>,
    memkeys: &Vec<G2Affine>,
    setup: &Setup,
    msg: &[u8],
) -> (Vec<usize>, G2Affine) {
    assert!(m <= n);
    let mut rng = rng();
    let mut positions = (0..n).choose_multiple(&mut rng, m).to_vec();
    positions.sort();
    let signatures = positions.iter().map(|i| {
        sign_with_mk_g2(secrets[*i], memkeys[*i], &*setup.prefix_apk(msg))
    });
    (
        positions.clone(),
        signatures
            .map(G2Projective::from)
            .sum::<G2Projective>()
            .into(),
    )
}

pub fn bench_threshold_sig_verification(c: &mut Criterion) {
    let n = 10;
    let (secrets, setup, memkeys) = threshold_setup(n);
    let m = 7; // threshold value
    let msg: &[u8] = b"Lorem ipsum, dolor sit amet";
    let (positions, sig) =
        random_threshold_sign(m, n, &secrets, &memkeys, &setup, msg);
    assert!(setup.verify_threshold(m, &sig, &positions, msg));

    let mut group = c.benchmark_group("Signature");
    group.bench_function("Threshold signature verification", |b| {
        b.iter(|| setup.verify_threshold(m, &sig, &positions, msg))
    });
    group.measurement_time(core::time::Duration::new(10, 0));
}

pub fn bench_multiple_threshold_sig_verification(c: &mut Criterion) {
    // computes nb * 3 * ML + nb * FE
    let n = 10;
    let nb = 20;
    // We use only one setup here and sign always the same message
    let msg: &[u8] = b"Lorem ipsum, dolor sit amet";
    let (secrets, setup, memkeys) = threshold_setup(n);

    let pos_and_sigs: Vec<(Vec<usize>, G2Affine)> = (0..nb)
        .map(|_| {
            let mut rng = rand::thread_rng();
            let m = rng.gen_range(1, n);
            random_threshold_sign(m, n, &secrets, &memkeys, &setup, msg)
        })
        .collect();

    for i in 0..pos_and_sigs.len() {
        let (pos, sig) = &pos_and_sigs[i];
        assert!(setup.verify_threshold(pos.len(), &sig, &pos, msg));
    }

    let mut group = c.benchmark_group("Signature");
    group.bench_function("One-by-one threshold sigs verification", |b| {
        b.iter(|| {
            for i in 0..pos_and_sigs.len() {
                let (pos, sig) = &pos_and_sigs[i];
                assert!(setup.verify_threshold(pos.len(), &sig, &pos, msg));
            }
        })
    });
    group.measurement_time(core::time::Duration::new(10, 0));
}

pub fn bench_multi_sig_verification(c: &mut Criterion) {
    // computes (nb+1) * ML + 1 * FE
    let n = 10;
    let nb = 20;
    // We use only one setup here and sign always the same message
    let msg: &[u8] = b"Lorem ipsum, dolor sit amet";
    let (secrets, setup, memkeys) = threshold_setup(n);

    let pos_and_sigs: Vec<(Vec<usize>, G2Affine)> = (0..nb)
        .map(|_| {
            let mut rng = rand::thread_rng();
            let m = rng.gen_range(1, n);
            random_threshold_sign(m, n, &secrets, &memkeys, &setup, msg)
        })
        .collect();

    let setups: Vec<&Setup> = (0..nb).map(|_| &setup).collect();
    let (_poss, sigs): (Vec<_>, Vec<_>) = pos_and_sigs.iter().cloned().unzip();
    let thresholds: Vec<usize> = _poss.iter().map(|pos| pos.len()).collect();
    let msgs: Vec<&[u8]> = (0..nb).map(|_| msg).collect();

    let poss: Vec<&[_]> = _poss.iter().map(|pos| pos.as_slice()).collect();
    assert!(verify_multiple_sig(
        &setups,
        &thresholds,
        &sigs,
        &poss,
        &msgs,
    ));

    let mut group = c.benchmark_group("Signature");
    group.bench_function("Mutli threshold sigs verification", |b| {
        b.iter(|| {
            assert!(verify_multiple_sig(
                &setups,
                &thresholds,
                &sigs,
                &poss,
                &msgs,
            ));
        })
    });
    group.measurement_time(core::time::Duration::new(10, 0));
}

pub fn bench_multi_aggregated_sig_verification(c: &mut Criterion) {
    let n = 10;
    let nb = 20;
    // We use only one setup here and sign always the same message but
    // this won't change the benchmarks.
    let msg: &[u8] = b"Lorem ipsum, dolor sit amet";
    let msgs: Vec<&[u8]> = (0..nb).map(|_| msg).collect();
    let (secrets, setup) = aggregation_setup(n);
    let setups: Vec<&Setup> = (0..nb).map(|_| &setup).collect();

    let pos_and_sigs: Vec<(Vec<usize>, G2Affine)> = (0..nb)
        .map(|_| {
            let mut rng = rand::thread_rng();
            let m = rng.gen_range(1, n);
            random_aggregated_sign(m, n, &secrets, &setup, msg)
        })
        .collect();
    let (_poss, sigs): (Vec<_>, Vec<_>) = pos_and_sigs.iter().cloned().unzip();

    let poss: Vec<&[_]> = _poss.iter().map(|pos| pos.as_slice()).collect();

    println!("VERIFICATION DOES NOT WORK !\n\n\n\n\n");

    assert!(verify_multi_aggregated(&setups, &sigs, &poss, &msgs));
    
    let mut group = c.benchmark_group("Signature");
    group.bench_function("Aggregated sig verification", |b| {
        b.iter(|| {
	    1+1
            // assert!(verify_multiple_sig(
            //     &setups,
            //     &thresholds,
            //     &sigs,
            //     &poss,
            //     &msgs,
            // ));
        })
    });
    group.measurement_time(core::time::Duration::new(10, 0));
}

criterion_group!(
    benches,
    // bench_single_sig_verification,
    // bench_threshold_sig_verification,
    // bench_multiple_threshold_sig_verification,
    // bench_multi_sig_verification
    bench_multi_aggregated_sig_verification
);
criterion_main!(benches);
