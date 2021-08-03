use criterion::{black_box, criterion_group, criterion_main, Criterion};
use group_threshold_cryptography::*;

pub fn bench_decryption(c: &mut Criterion) {
    use rand::SeedableRng;
    use rand_core::RngCore;

    const NUM_OF_TX: usize = 1000;

    fn share_combine_bench(num_msg: usize, num_shares: usize, num_entities: usize, msg_size: usize) -> impl Fn() {
        let rng = &mut rand::rngs::StdRng::seed_from_u64(0);

        type E = ark_bls12_381::Bls12_381;
        let threshold = num_shares * 2 / 3;

        let (pubkey, _, contexts) = setup::<E>(threshold, num_shares, num_entities);

        // let mut messages: Vec<[u8; NUM_OF_TX]> = vec![];
        let mut messages: Vec<Vec<u8>> = vec![];
        let mut ciphertexts: Vec<Ciphertext<E>> = vec![];
        let mut dec_shares: Vec<Vec<DecryptionShare<E>>> = Vec::with_capacity(ciphertexts.len());
        for j in 0..num_msg {
            // let mut msg: [u8; NUM_OF_TX] = [0u8; NUM_OF_TX];
            let mut msg: Vec<u8> = vec![];
            for _ in 0..msg_size {
                msg.push(0u8);
            }
            rng.fill_bytes(&mut msg[..]);
            messages.push(msg.clone());

            ciphertexts.push(encrypt::<_, E>(&messages[j], pubkey, rng));

            dec_shares.push(Vec::with_capacity(threshold));
            for i in 0..num_entities {
                dec_shares[j].push(contexts[i].create_share(&ciphertexts[j]));
            }
        }
        let prepared_blinded_key_shares = contexts[0].prepare_combine(&dec_shares[0]);

        let share_combine_prepared = move || {
            let c: Vec<Ciphertext<E>> = ciphertexts.clone();
            let shares: Vec<Vec<DecryptionShare<E>>> = dec_shares.clone();

            for i in 0..ciphertexts.len() {
                black_box(contexts[0].share_combine(
                    &c[i],
                    &shares[i],
                    &prepared_blinded_key_shares,
                ));
            }
        };

        share_combine_prepared
    }

    fn block_propose_bench(num_msg: usize, num_shares: usize, num_entities: usize, msg_size: usize) -> impl Fn() {
        let rng = &mut rand::rngs::StdRng::seed_from_u64(0);

        type E = ark_bls12_381::Bls12_381;
        let threshold = num_shares * 2 / 3;

        let (pubkey, _, contexts) = setup::<E>(threshold, num_shares, num_entities);

        // let mut messages: Vec<[u8; NUM_OF_TX]> = vec![];
        let mut messages: Vec<Vec<u8>> = vec![];
        let mut ciphertexts: Vec<Ciphertext<E>> = vec![];
        let mut dec_shares: Vec<Vec<DecryptionShare<E>>> = Vec::with_capacity(ciphertexts.len());
        for j in 0..num_msg {
            // let mut msg: [u8; NUM_OF_TX] = [0u8; NUM_OF_TX];
            let mut msg: Vec<u8> = vec![];
            for _ in 0..msg_size {
                msg.push(0u8);
            }
            rng.fill_bytes(&mut msg);
            messages.push(msg.clone());

            ciphertexts.push(encrypt::<_, E>(&messages[j], pubkey, rng));

            dec_shares.push(Vec::with_capacity(threshold));
            for i in 0..num_entities {
                dec_shares[j].push(contexts[i].create_share(&ciphertexts[j]));
            }
        }

        let block_proposer_prepared = move || {
            let rng = &mut ark_std::test_rng();
            let c: Vec<Ciphertext<E>> = ciphertexts.clone();
            let shares: Vec<Vec<DecryptionShare<E>>> = dec_shares.clone();

            contexts[0].batch_verify_decryption_shares(&c, &shares, rng);
            let prepared_blinded_key_shares = contexts[0].prepare_combine(&dec_shares[0]);

            for i in 0..ciphertexts.len() {
                black_box(contexts[0].share_combine(
                    &c[i],
                    &shares[i],
                    &prepared_blinded_key_shares,
                ));
            }
        };

        block_proposer_prepared
    }

    let mut group = c.benchmark_group("TPKE");
    group.sample_size(10);

    for msg_num in vec![10, 100, 1000].iter() {
        for msg_size in vec![100, 1000, 10000].iter() {
            let a = share_combine_bench(*msg_num, 8192, 150, *msg_size);
            group.measurement_time(core::time::Duration::new(30, 0));
            group.bench_function(format!("share_combine: threshold 8192*2/3 - #msg {} - msg-size = {} bytes", msg_num, msg_size), |b| {
                b.iter(|| a())
            });

            let a = block_propose_bench(*msg_num, 8192, 150, *msg_size);
            group.measurement_time(core::time::Duration::new(30, 0));
            group.bench_function(format!("block_propose: threshold 8192*2/3 - #msg {} - msg-size = {} bytes", msg_num, msg_size), |b| {
                b.iter(|| a())
            });
        }
    }
}

criterion_group!(benches, bench_decryption);
criterion_main!(benches);
