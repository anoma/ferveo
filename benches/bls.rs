#[macro_use]
extern crate criterion;

use criterion::Criterion;

use bls12_381::{G2Affine, G2Projective, Scalar};
use ferveo::bls::*;

// Fixed seed for reproducability
fn rng() -> rand::rngs::StdRng {
    use rand::SeedableRng;
    rand::rngs::StdRng::seed_from_u64(0)
}

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
    assert!(verify_g2_opt(&pubkeys[1], &sig1, msg));

    let mut group = c.benchmark_group("Signature");
    group.sample_size(10);
    // bench of the verification
    group.bench_function("Signature verification", |b| {
        b.iter(|| verify_g2(&pubkeys[1], &sig1, msg))
    });
    group.measurement_time(core::time::Duration::new(10, 0));
    // bench of the optimized verification
    group.bench_function("Optimized signature verification", |b| {
        b.iter(|| verify_g2_opt(&pubkeys[1], &sig1, msg))
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
    let s1 = secrets[1];
    let memkey1 = memkeys[1];
    let ts1: G2Projective =
        sign_with_mk_g2(s1, memkey1, &setup.prefix_apk(msg)).into();
    let s2 = secrets[2];
    let memkey2 = memkeys[2];
    let ts2: G2Projective =
        sign_with_mk_g2(s2, memkey2, &setup.prefix_apk(msg)).into();
    let sig: G2Affine = (ts1 + ts2).into();

    // check
    assert!(setup.verify_threshold(2, &sig, &[1, 2], msg));
    assert!(setup.verify_threshold_opt(2, &sig, &[1, 2], msg));

    // bench of the threshold verification
    group.bench_function("Threshold signature verification", |b| {
        b.iter(|| setup.verify_threshold(2, &sig, &[1, 2], msg))
    });
    group.measurement_time(core::time::Duration::new(10, 0));
    // bench of the optimized threshold verification
    group.bench_function("Optimized threshold signature verification", |b| {
        b.iter(|| setup.verify_threshold_opt(2, &sig, &[1, 2], msg))
    });
    group.measurement_time(core::time::Duration::new(10, 0));
}

criterion_group!(benches, bench_signature_verification);
criterion_main!(benches);
