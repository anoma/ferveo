use ark_bls12_381::*;
use ark_ec::*;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use redjubjub::*;
use std::convert::TryFrom;

use ark_bls12_381::*;
use ark_ff::Field;
use ark_std::UniformRand;
use ed25519_dalek::verify_batch;
use rand::thread_rng;

pub fn lagrange(c: &mut Criterion) {
    let rng = &mut ark_std::test_rng();
    let mut group = c.benchmark_group("lagrange running time");
    group.sample_size(10);

    group.measurement_time(core::time::Duration::new(20, 0));
    let mut u = vec![];
    for _ in 0..(8192 * 2 / 3) {
        u.push(Fr::rand(rng));
    }
    group.bench_function("BLS12-381 Fr 8192*2/3 lagrange coefficients", |b| {
        b.iter(|| {
            black_box(
                ferveo::SubproductDomain::<Fr>::new(u.clone())
                    .inverse_lagrange_coefficients()
                    //.iter()
                    //.map(|x| x.inverse())
                    //.collect::<Vec<_>>(),
            )
        })
    });

    use ark_ed_on_bls12_381 as jubjub;

    let mut u = vec![];
    for _ in 0..(8192 * 2 / 3) {
        u.push(jubjub::Fr::rand(rng));
    }

    group.bench_function("Jubjub Fr 8192*2/3 lagrange coefficients", |b| {
        b.iter(|| {
            black_box(
                ferveo::SubproductDomain::<jubjub::Fr>::new(u.clone())
                    .inverse_lagrange_coefficients()
                    //.iter()
                    //.map(|x| x.inverse())
                    //.collect::<Vec<_>>(),
            )
        })
    });
}

pub fn pairing(c: &mut Criterion) {
    let rng = &mut ark_std::test_rng();
    let mut group = c.benchmark_group("pairing running time");
    group.sample_size(10);

    type G1Prepared = <Bls12_381 as PairingEngine>::G1Prepared;
    type G2Prepared = <Bls12_381 as PairingEngine>::G2Prepared;

    let P = (0..100)
        .map(|i| {
            G1Affine::prime_subgroup_generator()
                .mul(Fr::rand(rng))
                .into_affine()
        })
        .collect::<Vec<G1Affine>>();
    let Q = (0..100)
        .map(|i| {
            G2Affine::prime_subgroup_generator()
                .mul(Fr::rand(rng))
                .into_affine()
        })
        .collect::<Vec<G2Affine>>();
    group.measurement_time(core::time::Duration::new(5, 0));
    group.bench_function("BLS12-381 pairing", |b| {
        b.iter(|| black_box(Bls12_381::pairing(P[0], Q[0])))
    });
    let PQ = &P
        .iter()
        .zip(Q.iter())
        .map(|(i, j)| (G1Prepared::from(*i), G2Prepared::from(*j)))
        .collect::<Vec<(G1Prepared, G2Prepared)>>();

    group.bench_function("BLS12-381 G1Prepared", |b| {
        b.iter(|| {
            black_box(
                P.iter().map(|i| G1Prepared::from(*i)).collect::<Vec<_>>(),
            )
        })
    });
    group.bench_function("BLS12-381 G2Prepared", |b| {
        b.iter(|| {
            black_box(
                Q.iter().map(|i| G2Prepared::from(*i)).collect::<Vec<_>>(),
            )
        })
    });
    group.bench_function("BLS12-381 product_of_pairing G2 prepared", |b| {
        b.iter(|| {
            (
                black_box(
                    P.iter().map(|i| G1Prepared::from(*i)).collect::<Vec<_>>(),
                ),
                black_box(Bls12_381::product_of_pairings(PQ.iter())),
            )
        })
    });
    group.bench_function("BLS12-381 product_of_pairing both prepared", |b| {
        b.iter(|| black_box(Bls12_381::product_of_pairings(PQ.iter())))
    });

    let Q_j = G2Affine::prime_subgroup_generator()
        .mul(Fr::rand(rng))
        .into_affine();
    let r = Fr::rand(rng);

    group.bench_function("BLS12-381 100 linear combine G1", |b| {
        b.iter(|| black_box(P.iter().map(|i| i.mul(r)).sum::<G1Projective>()))
    });

    group.bench_function("BLS12-381 100 linear combine G2", |b| {
        b.iter(|| black_box(Q.iter().map(|i| i.mul(r)).sum::<G2Projective>()))
    });

    let P = (0..(8192 * 2 / 3))
        .map(|i| {
            G1Affine::prime_subgroup_generator()
                .mul(Fr::rand(rng))
                .into_affine()
        })
        .collect::<Vec<G1Affine>>();

    let mut u = vec![];
    for _ in 0..(8192 * 2 / 3) {
        u.push(Fr::rand(rng));
    }

    let lagrange = ferveo::SubproductDomain::<Fr>::new(u.clone())
        .inverse_lagrange_coefficients()
        .iter()
        .map(|x| x.inverse().unwrap())
        .collect::<Vec<_>>();

    group.bench_function("BLS12-381 8192*2/3 share combine G1", |b| {
        b.iter(|| {
            black_box(
                P.iter()
                    .zip(lagrange.iter())
                    .map(|(i, lambda)| i.mul(*lambda))
                    .sum::<G1Projective>()
                    .into_affine(),
            )
        })
    });

    use ark_ec::msm::FixedBaseMSM;
    let window_size = FixedBaseMSM::get_mul_window_size(3000);

    use ark_ff::PrimeField;
    let scalar_bits = Fr::size_in_bits();
    let base_table = FixedBaseMSM::get_window_table(
        scalar_bits,
        window_size,
        Q_j.into_projective(),
    );
    group.measurement_time(core::time::Duration::new(20, 0));

    group.bench_function("BLS12-381 100 MSM linear combine G2", |b| {
        b.iter(|| {
            black_box(
                Q.iter()
                    .map(|i| {
                        FixedBaseMSM::multi_scalar_mul::<G2Projective>(
                            scalar_bits,
                            window_size,
                            &base_table,
                            &[r],
                        )[0]
                    })
                    .sum::<G2Projective>(),
            )
        })
    });

    let Q = (0..(8192 * 2 / 3))
        .map(|i| {
            G2Affine::prime_subgroup_generator()
                .mul(Fr::rand(rng))
                .into_affine()
        })
        .collect::<Vec<G2Affine>>();

    group.bench_function("BLS12-381 8192*2/3 G2Prepared", |b| {
        b.iter(|| {
            black_box(
                Q.iter().map(|i| G2Prepared::from(*i)).collect::<Vec<_>>(),
            )
        })
    });
    let base_tables = Q
        .iter()
        .map(|q| {
            FixedBaseMSM::get_window_table(
                scalar_bits,
                window_size,
                q.into_projective(),
            )
        })
        .collect::<Vec<_>>();

    group.bench_function("BLS12-381 share combine precompute", |b| {
        b.iter(|| {
            black_box(
                Q.iter()
                    .zip(lagrange.iter())
                    .map(|(i, lambda)| {
                        FixedBaseMSM::multi_scalar_mul::<G2Projective>(
                            scalar_bits,
                            window_size,
                            &base_table,
                            &[*lambda],
                        )[0]
                    })
                    .sum::<G2Projective>(),
            )
        })
    });

    use ark_ed_on_bls12_381 as jubjub;
    let P = (0..(8192 * 2 / 3))
        .map(|i| {
            jubjub::EdwardsAffine::prime_subgroup_generator()
                .mul(jubjub::Fr::rand(rng))
                .into_affine()
        })
        .collect::<Vec<_>>();

    let mut u = vec![];
    for _ in 0..(8192 * 2 / 3) {
        u.push(jubjub::Fr::rand(rng));
    }
    /*let lagrange = ferveo::SubproductDomain::<jubjub::Fr>::new(u.clone())
    .inverse_lagrange_coefficients()
    .iter()
    .map(|x| x.inverse().unwrap())
    .collect::<Vec<_>>();*/

    group.bench_function("8192*2/3 share combine Jubjub", |b| {
        b.iter(|| {
            black_box(
                P.iter()
                    .zip(u.iter())
                    .map(|(i, lambda)| i.mul(*lambda))
                    .sum::<jubjub::EdwardsProjective>()
                    .into_affine(),
            )
        })
    });
}

enum Item {
    SpendAuth {
        vk_bytes: VerificationKeyBytes<SpendAuth>,
        sig: Signature<SpendAuth>,
    },
    Binding {
        vk_bytes: VerificationKeyBytes<Binding>,
        sig: Signature<Binding>,
    },
}

fn sigs_with_distinct_keys() -> impl Iterator<Item = Item> {
    use rand::{thread_rng, Rng};
    std::iter::repeat_with(|| {
        let mut rng = thread_rng();
        let msg = b"Bench";
        match rng.gen::<u8>() % 2 {
            0 => {
                let sk = SigningKey::<SpendAuth>::new(thread_rng());
                let vk_bytes = VerificationKey::from(&sk).into();
                let sig = sk.sign(thread_rng(), &msg[..]);
                Item::SpendAuth { vk_bytes, sig }
            }
            1 => {
                let sk = SigningKey::<Binding>::new(thread_rng());
                let vk_bytes = VerificationKey::from(&sk).into();
                let sig = sk.sign(thread_rng(), &msg[..]);
                Item::Binding { vk_bytes, sig }
            }
            _ => panic!(),
        }
    })
}

pub fn redjubjub(c: &mut Criterion) {
    let mut group = c.benchmark_group("Redjubjub Batch Verification");
    group.sample_size(10);
    group.measurement_time(core::time::Duration::new(5, 0));

    for &n in [1, 100usize, 1024 * 2 / 3, 8192 * 2 / 3].iter() {
        let sigs = sigs_with_distinct_keys().take(n).collect::<Vec<_>>();

        group.bench_with_input(
            criterion::BenchmarkId::new("Batched verification", n),
            &sigs,
            |b, sigs| {
                b.iter(|| {
                    let mut batch = batch::Verifier::new();
                    for item in sigs.iter() {
                        let msg = b"Bench";
                        match item {
                            Item::SpendAuth { vk_bytes, sig } => {
                                batch.queue((*vk_bytes, *sig, msg));
                            }
                            Item::Binding { vk_bytes, sig } => {
                                batch.queue((*vk_bytes, *sig, msg));
                            }
                        }
                    }
                    batch.verify(thread_rng())
                })
            },
        );
    }
    group.finish();
}

fn ed25519_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("Ed25519 Batch Verification");
    group.sample_size(10);
    group.measurement_time(core::time::Duration::new(5, 0));

    use ed25519_dalek::Signer;
    use ed25519_dalek::{Keypair, PublicKey, Signature};
    for &n in [1, 100usize, 1024 * 2 / 3, 8192 * 2 / 3].iter() {
        let mut csprng = rand_old::thread_rng();
        let keypairs: Vec<Keypair> =
            (0..n).map(|_| Keypair::generate(&mut csprng)).collect();
        let msg: &[u8] =
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let messages: Vec<&[u8]> = (0..n).map(|_| msg).collect();
        let signatures: Vec<Signature> =
            keypairs.iter().map(|key| key.sign(&msg)).collect();
        let public_keys: Vec<PublicKey> =
            keypairs.iter().map(|key| key.public).collect();

        group.bench_with_input(
            criterion::BenchmarkId::new(
                "Ed25519 batch signature verification",
                n,
            ),
            &(messages, signatures, public_keys),
            |b, sigs| {
                b.iter(|| verify_batch(&sigs.0, &sigs.1, &sigs.2));
            },
        );
    }
}

pub fn bench_batch_inverse(c: &mut Criterion) {
    use ark_std::UniformRand;
    let rng = &mut ark_std::test_rng();
    let n = 8192 * 2 / 3;
    let a = (0..n)
        .map(|_| ark_bls12_381::Fr::rand(rng))
        .collect::<Vec<_>>();

    let mut group = c.benchmark_group("BLS12-381 Batch inverse");
    group.sample_size(10);
    group.measurement_time(core::time::Duration::new(20, 0));
    group.bench_with_input(
        criterion::BenchmarkId::new("BLS12-381 Batch inverse", n),
        &a,
        |b, a| {
            b.iter(|| black_box(ark_ff::batch_inversion(&mut a.clone())));
        },
    );
}

criterion_group!(
    ec,
    pairing,
    redjubjub,
    ed25519_batch,
    lagrange,
    bench_batch_inverse
);

criterion_group!(micro, bench_batch_inverse);
