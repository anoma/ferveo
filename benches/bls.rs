#[macro_use]
extern crate criterion;

use bls12_381::{G1Affine, G2Affine, G2Projective, Scalar};
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

pub fn threshold_setup(
    n: usize,
) -> (Vec<Scalar>, Setup, Vec<Vec<G2Affine>>, Vec<G2Affine>) {
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
    (secrets, setup, mk_frags, memkeys)
}

pub fn random_sign(
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
    let (secrets, setup, mk_frags, memkeys) = threshold_setup(n);
    let m = 7; // threshold value
    let msg: &[u8] = b"Lorem ipsum, dolor sit amet";
    let (positions, sig) = random_sign(m, n, &secrets, &memkeys, &setup, msg);
    assert!(setup.verify_threshold(m, &sig, &positions, msg));

    let mut group = c.benchmark_group("Signature");
    group.bench_function("Threshold signature verification", |b| {
        b.iter(|| setup.verify_threshold(m, &sig, &positions, msg))
    });
    group.measurement_time(core::time::Duration::new(10, 0));
}

pub fn bench_multiple_threshold_sig_verification(c: &mut Criterion) {
    let n = 10;
    let nb = 12;
    // We use only one setup here and sign always the same message
    let msg: &[u8] = b"Lorem ipsum, dolor sit amet";
    let (secrets, setup, mk_frags, memkeys) = threshold_setup(n);

    let pos_and_sigs: Vec<(Vec<usize>, G2Affine)> = (0..nb)
        .map(|i| {
            let mut rng = rand::thread_rng();
            let m = rng.gen_range(0, n);
            random_sign(m, n, &secrets, &memkeys, &setup, msg)
        })
        .collect();

    println!("len = {}", pos_and_sigs.len());

    pos_and_sigs.iter().map(|pos_sig| {
        assert!(setup.verify_threshold(
            pos_sig.0.len(),
            &pos_sig.1,
            &pos_sig.0,
            msg
        ));
    });

    println!("THIS BENCH IS NOT WORKING\n\n\n\n");

    let mut group = c.benchmark_group("Signature");
    group.bench_function("One-by-one threshold sigs verification", |b| {
        b.iter(|| {
            pos_and_sigs.iter().map(|pos_sig| {
                setup.verify_threshold(
                    pos_sig.0.len(),
                    &pos_sig.1,
                    &pos_sig.0,
                    msg,
                )
            })
        })
    });
    group.measurement_time(core::time::Duration::new(10, 0));
}

pub fn bench_multi_sig_verification(c: &mut Criterion) {}

pub fn bench_signature_verification(c: &mut Criterion) {
    // create three secret keys and the associated public keys
    let mut rng = rng();

    let mut keypairs: Vec<Keypair> = (0..3)
        .map(|_| <Scalar as ff::Field>::random(&mut rng).into())
        .collect();
    keypairs.sort();
    let (secrets, pubkeys): (Vec<_>, Vec<_>) =
        keypairs.iter().map(|kp| (kp.secret, kp.pubkey)).unzip();
    let msg: &[u8] = b"Lorem ipsum, dolor sit amet";

    //
    // simple signature
    //
    let sig1 = sign_g2(secrets[1], &msg);
    // check
    assert!(verify_g2(&pubkeys[1], &sig1, msg));

    let mut group = c.benchmark_group("Signature");
    group.sample_size(10);
    // bench of the verification
    group.bench_function("Signature verification", |b| {
        b.iter(|| verify_g2(&pubkeys[1], &sig1, msg))
    });
    group.measurement_time(core::time::Duration::new(10, 0));

    //
    // threshold signature
    //
    // create a setup from the public keys, i.e {pubkeys, coeffs, apk}.
    let setup: Setup = pubkeys.into_iter().collect();
    // create the membership keys of each participants.
    let mk_frags: Vec<Vec<_>> = keypairs
        .into_iter()
        .map(|kp| setup.memkey_frags(&kp))
        .collect();
    // generate the `i`th memkey
    let memkey = |i: usize| {
        let frags: Vec<_> = mk_frags.iter().map(|cs| cs[i]).collect();
        setup.memkey(i, &frags)
    };
    let memkeys: Vec<_> = (0..3).map(memkey).map(Option::unwrap).collect();
    // example with two participants among three.
    let msg1: &[u8] = b"hello";
    let s1 = secrets[1];
    let memkey1 = memkeys[1];
    let ts1: G2Projective =
        sign_with_mk_g2(s1, memkey1, &setup.prefix_apk(msg1)).into();
    let s2 = secrets[2];
    let memkey2 = memkeys[2];
    let ts2: G2Projective =
        sign_with_mk_g2(s2, memkey2, &setup.prefix_apk(msg1)).into();
    let sig: G2Affine = (ts1 + ts2).into();

    // check
    assert!(setup.verify_threshold(2, &sig, &[1, 2], msg1));

    // bench of the optimized threshold verification
    group.bench_function("Threshold signature verification", |b| {
        b.iter(|| setup.verify_threshold(2, &sig, &[1, 2], msg1))
    });
    group.measurement_time(core::time::Duration::new(10, 0));

    //
    // Multi threshold verification
    //

    // Another example with two participants among three.
    let setup2: &Setup = &setup;
    let msg2: &[u8] = b"bonjour";
    let s0 = secrets[0];
    let memkey0 = memkeys[0];
    let ts0: G2Projective =
        sign_with_mk_g2(s0, memkey0, &setup.prefix_apk(msg2)).into();
    let ts11: G2Projective =
        sign_with_mk_g2(s1, memkey1, &setup.prefix_apk(msg2)).into();
    let sig_prime: G2Affine = (ts0 + ts11).into();

    // check
    assert!((*setup2).verify_threshold(2, &sig_prime, &[0, 1], msg2));

    assert!(verify_multiple_sig(
        &[&setup, setup2],
        &[2, 2],
        &[sig, sig_prime],
        &[&[1, 2], &[0, 1]],
        &[msg1, msg2]
    ));

    // bench of the multi signature verification
    group.bench_function("Multi threshold signature verification", |b| {
        b.iter(|| {
            verify_multiple_sig(
                &[&setup, setup2],
                &[2, 2],
                &[sig, sig_prime],
                &[&[1, 2], &[0, 1]],
                &[msg1, msg2],
            )
        })
    });
    group.measurement_time(core::time::Duration::new(10, 0));
}

criterion_group!(
    benches,
    // bench_single_sig_verification,
    // bench_threshold_sig_verification,
    bench_multiple_threshold_sig_verification
);
criterion_main!(benches);
