use criterion::{black_box, criterion_group, criterion_main, Criterion};

use ark_bls12_381::*;
use ark_ec::*;
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
}

pub fn work(
    G: G1Prepared,
    H: G2Prepared,
    ciphertexts: &[(G1Affine, G2Affine, G2Affine)],
    D: &[Vec<G1Affine>],
    P: &[G2Prepared],
    B: &[G2Affine],
) {
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
    );

    D.iter().zip(lagrange.chunks(n/100)).map( | (D_i, lambda_i)  
    //  S_{i,j} = e( D_{i,j}, [\sum_{\omega_j \in \Omega_i} \lambda_{\omega_j}(0)] [b] Z_{i,\omega_j} )
}
