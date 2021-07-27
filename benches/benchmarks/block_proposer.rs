use criterion::{black_box, criterion_group, criterion_main, Criterion};

use ark_bls12_381::*;
use ark_ec::msm::FixedBaseMSM;
use ark_ec::*;
use ark_ff::PrimeField;
use ark_std::One;
use ark_std::UniformRand;
use ferveo::*;
use itertools::Itertools;

type G1Prepared = <Bls12_381 as PairingEngine>::G1Prepared;
type G2Prepared = <Bls12_381 as PairingEngine>::G2Prepared;
type Fqk = <Bls12_381 as PairingEngine>::Fqk;

pub fn block_proposer(c: &mut Criterion) {
    let rng = &mut ark_std::test_rng();
    let mut group = c.benchmark_group("lagrange running time");
    group.sample_size(10);

    group.measurement_time(core::time::Duration::new(20, 0));

    use ark_ff::PrimeField;
    let scalar_bits = Fr::size_in_bits();
    let window_size = FixedBaseMSM::get_mul_window_size(1000);

    let B = (0..8192)
        .map(|_| G2Affine::prime_subgroup_generator().mul(Fr::rand(rng)))
        .collect::<Vec<_>>();

    let base_tables = B
        .iter()
        .map(|B_j| {
            FixedBaseMSM::get_window_table(scalar_bits, window_size, *B_j)
        })
        .collect::<Vec<_>>();
    group.measurement_time(core::time::Duration::new(20, 0));
}

pub fn work(
    G: G1Prepared,
    H: G2Prepared,
    ciphertexts: &[(G1Affine, G2Affine, G2Affine)],
    D: &[Vec<G1Affine>],
    P: &[G2Prepared],
    B: &[Vec<Vec<G2Affine>>],
    window_size: usize,
) {
    let scalar_bits = Fr::size_in_bits();

    let rng = &mut rand::thread_rng();
    // e(U, H_{\mathbb{G}_2} (U)) = e(G, W)

    for (U, H_G, W) in ciphertexts.iter() {
        let prep = [
            (G1Prepared::from(*U), G2Prepared::from(*H_G)),
            (G.clone(), G2Prepared::from(*W)),
        ];
        black_box(Bls12_381::product_of_pairings(prep.iter()) == Fqk::one());
    }

    let V = D.len();
    let T = ciphertexts.len();
    let alpha = (0..V * T).map(|_| Fr::rand(rng)).collect::<Vec<_>>();

    let prepared_alpha_U_j = G1Prepared::from(
        ciphertexts
            .iter()
            .zip(alpha.chunks(V))
            .map(|((U_j, _, _), alpha_j)| U_j.mul(alpha_j.iter().sum::<Fr>()))
            .sum::<G1Projective>()
            .into_affine(),
    );

    let prepared_alpha_D_i = D
        .iter()
        .zip(P.iter())
        .map(|(D_ij, P_i)| {
            (
                G1Prepared::from(
                    D_ij.iter()
                        .zip(alpha.windows(T))
                        .map(|(D_i, alpha_i)| {
                            D_i.mul(alpha_i.iter().sum::<Fr>())
                        })
                        .sum::<G1Projective>()
                        .into_affine(),
                ),
                P_i.clone(),
            )
        })
        .chain([(prepared_alpha_U_j, H)])
        .collect::<Vec<_>>();

    //  \prod_i e(\sum_{j} [\alpha_{i,j}] D_{i,j}, P_i) = e(\sum_{j} [\sum_i \alpha_{i,j} U_j], H)
    black_box(Bls12_381::product_of_pairings(prepared_alpha_D_i.iter()));

    let n = B.len() * 2 / 3;
    let mut u = Vec::with_capacity(n);
    for _ in 0..n {
        u.push(Fr::rand(rng));
    }
    let lagrange = ferveo::batch_inverse(
        &ferveo::SubproductDomain::<Fr>::new(u.clone())
            .inverse_lagrange_coefficients(),
    )
    .unwrap();

    let right = B
        .iter()
        .zip(lagrange.iter())
        .map(|(B_ij, lambda)| {
            FixedBaseMSM::multi_scalar_mul::<G2Projective>(
                scalar_bits,
                window_size,
                &B_ij,
                &[*lambda],
            )
        })
        .chunks(n / V)
        .map(|B_i| B_i.sum.sum::<G2Projective>())
        .collect::<Vec<_>>();

    let left = D
        .iter()
        .map(|D_i| D_i.iter().map(|D_ij| {}))
        .collect::<Vec<_>>();
    //  S_{i,j} = e( D_{i,j}, [\sum_{\omega_j \in \Omega_i} \lambda_{\omega_j}(0)] [b] Z_{i,\omega_j} )
}
