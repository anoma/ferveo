use crate::subproductdomain::*;
use ark_ec::group::Group;
use ark_ec::PairingEngine;
use ark_ff::{Field, One, PrimeField, Zero};
use ark_poly::{
    polynomial::univariate::DensePolynomial, EvaluationDomain, UVPolynomial,
};
use ark_poly_commit::kzg10::UniversalParams;
use ark_serialize::*;

use ark_ec::AffineCurve;

/// Opening proofs of a commitment on a large domain
pub struct DomainProof<E: PairingEngine> {
    /// This is a vector of commitments to the witness polynomials
    /// over a domain 1, omega, omega^2, ..., omega^{n-1}
    /// where omega is a primitive n'th root of unity
    pub w: Vec<E::G1Projective>,
    /// Scale factor whose multiplication is deferred until the proofs are combined
    pub scale: E::Fr,
}

impl<E: PairingEngine> DomainProof<E> {
    /// Combine opening proofs onto a subset of the domain
    /// represented by the SubproductDomain s
    pub fn combine_at_domain(
        &self,
        domain: &std::ops::Range<usize>, // Domain is omega^{start}, ..., omega^{end-1}
        s: &SubproductDomain<E::Fr>,     // SubproductDomain of the domain
    ) -> CombinedDomainProof<E> {
        let lagrange_coeff = s.inverse_lagrange_coefficients();
        let mut total = E::G1Projective::zero();
        for (c_i, point) in
            lagrange_coeff.iter().zip(self.w[domain.clone()].iter())
        {
            total += point.mul(&c_i.inverse().unwrap());
        }
        // total.into(),
        // NOTE: if the ifft had not multiplied by domain_size_inv
        CombinedDomainProof {
            w: total.mul(&self.scale).into(),
        }
    }

    pub fn new(
        powers_of_g: &[E::G1Affine],
        polynomial: &DensePolynomial<E::Fr>,
        domain: &ark_poly::Radix2EvaluationDomain<E::Fr>,
    ) -> Result<DomainProof<E>, anyhow::Error> {
        let m = polynomial.coeffs.len() - 1;
        let p = powers_of_g[0..m].to_vec();
        let (mut h, domain_size_inv) =
            toeplitz_mul::<E, false>(polynomial, &p, domain.size())?;

        domain.fft_in_place(&mut h);

        Ok(DomainProof {
            w: h,
            scale: domain_size_inv,
        })
    }
}

#[derive(Debug, Clone, Copy, CanonicalSerialize, CanonicalDeserialize)]
pub struct CombinedDomainProof<E: PairingEngine> {
    pub w: E::G1Affine,
}

impl<E: PairingEngine> CombinedDomainProof<E> {
    /// Verifies that `evals` are the evaluation at `s` of the polynomial
    /// committed inside `comm` where `s` is a constructed SubproductDomain
    pub fn check_at_domain(
        &self,
        powers_of_g: &[E::G1Affine],
        powers_of_h: &[E::G2Affine],
        comm: &E::G1Affine,
        evals: &[E::Fr], // Evaluations at the SubproductDomain
        s: &SubproductDomain<E::Fr>, // SubproductDomain of the evaluation domain
    ) -> Result<bool, anyhow::Error> {
        let evaluation_polynomial = s.interpolate(evals);

        let evaluation_polynomial_commitment =
            g1_commit::<E>(powers_of_g, &evaluation_polynomial)?;

        let s_commitment = g2_commit::<E>(powers_of_h, &s.t.m)?;
        Ok(self.check_at_domain_with_commitments(
            powers_of_h,
            comm,
            &s_commitment,
            &evaluation_polynomial_commitment,
        ))
    }

    /// Check combined domain proof with precomputed commitments
    pub fn check_at_domain_with_commitments(
        &self,
        powers_of_h: &[E::G2Affine],
        comm: &E::G1Affine,
        s_commitment: &E::G2Affine, // G2 Commitment to the SubproductDomain
        evaluation_polynomial_commitment: &E::G1Affine,
    ) -> bool {
        let inner = comm.into_projective()
            - evaluation_polynomial_commitment.into_projective();

        E::pairing(inner, powers_of_h[0])
            == E::pairing(self.w, s_commitment.into_projective())
    }
}

pub fn g2_commit<E: PairingEngine>(
    powers_of_h: &[E::G2Affine],
    polynomial: &DensePolynomial<E::Fr>,
) -> Result<E::G2Affine, anyhow::Error> {
    use ark_ec::msm::VariableBaseMSM;
    //TODO: check degree is a private
    /*Self::check_degree_is_too_large(
        polynomial.degree(),
        powers.size(),
    )?;*/

    let (num_leading_zeros, plain_coeffs) =
        skip_leading_zeros_and_convert_to_bigints(polynomial);

    let commitment = VariableBaseMSM::multi_scalar_mul(
        &powers_of_h[num_leading_zeros..],
        &plain_coeffs,
    );
    Ok(commitment.into())
}

pub fn g1_commit<E: PairingEngine>(
    powers_of_g: &[E::G1Affine],
    polynomial: &DensePolynomial<E::Fr>,
) -> Result<E::G1Affine, anyhow::Error> {
    use ark_ec::msm::VariableBaseMSM;
    //TODO: check degree is a private
    /*Self::check_degree_is_too_large(
        polynomial.degree(),
        powers.size(),
    )?;*/

    let (num_leading_zeros, plain_coeffs) =
        skip_leading_zeros_and_convert_to_bigints(polynomial);

    let commitment = VariableBaseMSM::multi_scalar_mul(
        &powers_of_g[num_leading_zeros..],
        &plain_coeffs,
    );
    Ok(commitment.into())
}

pub fn setup<E: PairingEngine, R: rand::RngCore>(
    max_degree: usize,
    rng: &mut R,
) -> Result<(UniversalParams<E>, Vec<E::G2Affine>), anyhow::Error> {
    use ark_ec::msm::FixedBaseMSM;
    use ark_ec::ProjectiveCurve;
    use ark_std::UniformRand;
    if max_degree < 1 {
        return Err(anyhow::anyhow!("DegreeIsZero"));
    }
    let beta = E::Fr::rand(rng);
    let g = E::G1Projective::rand(rng);
    let gamma_g = E::G1Projective::rand(rng);
    let h = E::G2Projective::rand(rng);

    let mut powers_of_beta = vec![E::Fr::one()];

    let mut cur = beta;
    for _ in 0..max_degree {
        powers_of_beta.push(cur);
        cur *= &beta;
    }

    let window_size = FixedBaseMSM::get_mul_window_size(max_degree + 1);

    let scalar_bits = E::Fr::size_in_bits();
    let g_table = FixedBaseMSM::get_window_table(scalar_bits, window_size, g);
    let powers_of_g = FixedBaseMSM::multi_scalar_mul::<E::G1Projective>(
        scalar_bits,
        window_size,
        &g_table,
        &powers_of_beta,
    );

    let h_table = FixedBaseMSM::get_window_table(scalar_bits, window_size, h);
    let powers_of_h = FixedBaseMSM::multi_scalar_mul::<E::G2Projective>(
        scalar_bits,
        window_size,
        &h_table,
        &powers_of_beta,
    );

    let gamma_g_table =
        FixedBaseMSM::get_window_table(scalar_bits, window_size, gamma_g);
    let mut powers_of_gamma_g = FixedBaseMSM::multi_scalar_mul::<E::G1Projective>(
        scalar_bits,
        window_size,
        &gamma_g_table,
        &powers_of_beta,
    );
    // Add an additional power of gamma_g, because we want to be able to support
    // up to D queries.
    powers_of_gamma_g.push(powers_of_gamma_g.last().unwrap().mul(&beta));

    let powers_of_g =
        E::G1Projective::batch_normalization_into_affine(&powers_of_g);

    let powers_of_h =
        E::G2Projective::batch_normalization_into_affine(&powers_of_h);
    let powers_of_gamma_g =
        E::G1Projective::batch_normalization_into_affine(&powers_of_gamma_g)
            .into_iter()
            .enumerate()
            .collect();

    let h = h.into_affine();
    let beta_h = h.mul(beta).into_affine();
    let prepared_h = h.into();
    let prepared_beta_h = beta_h.into();

    let pp = UniversalParams {
        powers_of_g,
        powers_of_gamma_g,
        h,
        beta_h,
        neg_powers_of_h: ark_std::collections::BTreeMap::new(),
        prepared_h,
        prepared_beta_h,
    };
    Ok((pp, powers_of_h))
}
pub fn skip_leading_zeros_and_convert_to_bigints<F: PrimeField>(
    p: &DensePolynomial<F>,
) -> (usize, Vec<F::BigInt>) {
    let mut num_leading_zeros = 0;
    while num_leading_zeros < p.coeffs().len()
        && p.coeffs()[num_leading_zeros].is_zero()
    {
        num_leading_zeros += 1;
    }
    let coeffs = convert_to_bigints::<F>(&p.coeffs()[num_leading_zeros..]);
    (num_leading_zeros, coeffs)
}

pub fn convert_to_bigints<F: PrimeField>(p: &[F]) -> Vec<F::BigInt> {
    let coeffs = ark_std::cfg_iter!(p)
        .map(|s| s.into_repr())
        .collect::<Vec<_>>();
    coeffs
}

#[cfg(test)]
type KZG = ark_poly_commit::kzg10::KZG10<Curve, DensePolynomial<Scalar>>;
use ark_poly_commit::kzg10::{Powers, VerifierKey};

pub fn trim<E: ark_ec::PairingEngine>(
    pp: &UniversalParams<E>,
    mut supported_degree: usize,
) -> Result<(Powers<E>, VerifierKey<E>), anyhow::Error> {
    if supported_degree == 1 {
        supported_degree += 1;
    }
    let powers_of_g = pp.powers_of_g[..=supported_degree].to_vec();
    let powers_of_gamma_g = (0..=supported_degree)
        .map(|i| pp.powers_of_gamma_g[&i])
        .collect();

    let powers = Powers {
        powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
        powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
    };
    let vk = VerifierKey {
        g: pp.powers_of_g[0],
        gamma_g: pp.powers_of_gamma_g[&0],
        h: pp.h,
        beta_h: pp.beta_h,
        prepared_h: pp.prepared_h.clone(),
        prepared_beta_h: pp.prepared_beta_h.clone(),
    };
    Ok((powers, vk))
}

#[cfg(test)]
use crate::*;

#[test]
fn test_open() {
    use ark_ec::ProjectiveCurve;
    use ark_poly::Polynomial;
    use ark_poly_commit::kzg10::Proof;
    let rng = &mut ark_std::test_rng();

    let n = 9;
    let total_weight = 1 << n;
    {
        let degree = 2 * total_weight / 3;
        let (pp, _powers_of_h) = setup::<Curve, _>(degree, rng).unwrap();
        let (ck, vk) = trim(&pp, degree).unwrap();

        for _ in 0..10 {
            let p = DensePolynomial::<Scalar>::rand(degree, rng);

            let (comm, _) = KZG::commit(&ck, &p, None, None).unwrap();
            //let comm = g1_commit::<Curve>(&ck.powers_of_g, &p);
            let domain =
                ark_poly::Radix2EvaluationDomain::<Scalar>::new(total_weight)
                    .unwrap();

            let proof = DomainProof::<Curve>::new(&ck.powers_of_g, &p, &domain)
                .unwrap();

            let mut share_domain = Vec::with_capacity(domain.size());
            let mut t = Scalar::one();
            for _ in 0..1 << domain.log_size_of_group {
                share_domain.push(t);
                t *= domain.group_gen;
            }

            let mut point = Scalar::one();

            for proof_projective in proof.w.iter() {
                let kzg_proof = Proof {
                    w: proof_projective.into_affine(),
                    random_v: None,
                };
                let value = p.evaluate(&point);
                assert!(
                    KZG::check(&vk, &comm, point, value, &kzg_proof,).unwrap()
                );
                point *= domain.group_gen;
            }
        }
    }
}

#[test]
fn test_toeplitz() {
    use ark_ec::{AffineCurve, ProjectiveCurve};
    let rng = &mut ark_std::test_rng();

    let max_degree = 50;
    let pp = KZG::setup(max_degree, false, rng).unwrap();

    for total_weight in 50..75 {
        for degree in 30..total_weight {
            let (ck, _) = trim(&pp, degree).unwrap();

            for _ in 0..4 {
                let polynomial = DensePolynomial::<Scalar>::rand(degree, rng);

                let coeffs = polynomial.coeffs();
                let m = polynomial.coeffs.len() - 1;

                let (h, _) = toeplitz_mul::<Curve, true>(
                    &polynomial,
                    &ck.powers_of_g[0..m],
                    total_weight,
                )
                .unwrap();

                let h = h
                    .iter()
                    .map(|p| p.into_affine())
                    .collect::<Vec<G1Affine>>();

                for i in 1..=m {
                    let mut total = G1Projective::zero();
                    for j in 0..=m - i {
                        total = total + (ck.powers_of_g[j].mul(coeffs[i + j]));
                    }
                    assert_eq!(G1Affine::from(total), h[i - 1]);
                }
            }
        }
    }
}

#[test]
fn test_all() {
    use crate::subproductdomain::*;
    use ark_poly::Polynomial;
    let rng = &mut ark_std::test_rng();

    let n = 10;
    let total_weight = 1 << n;
    {
        let degree = 2 * total_weight / 3;
        let (pp, powers_of_h) = setup::<Curve, _>(degree, rng).unwrap();
        let (ck, _) = trim(&pp, degree).unwrap();

        for _ in 0..1 {
            let p = DensePolynomial::<Scalar>::rand(degree, rng);

            //let (comm, _) = KZG::commit(&ck, &p, None, None).unwrap();
            let comm = g1_commit::<Curve>(&ck.powers_of_g, &p);

            let p_comm =
                g1_commit::<crate::Curve>(&ck.powers_of_g, &p).unwrap();
            let domain =
                ark_poly::Radix2EvaluationDomain::<Scalar>::new(total_weight)
                    .unwrap();

            let mut share_domain =
                Vec::with_capacity(1 << domain.log_size_of_group);
            let mut t = Scalar::one();
            for _ in 0..1 << domain.log_size_of_group {
                share_domain.push(t);
                t *= domain.group_gen;
            }

            let share_domain = share_domain[5..100].to_vec();
            let share_domain = SubproductDomain::new(share_domain);

            let evals = share_domain
                .u
                .iter()
                .map(|x| p.evaluate(x))
                .collect::<Vec<Scalar>>();

            let poly = share_domain.interpolate(&evals);

            let proof = DomainProof::<Curve>::new(&ck.powers_of_g, &p, &domain)
                .unwrap();
            let proof = proof.combine_at_domain(&(5..100), &share_domain);

            assert!(proof
                .check_at_domain(
                    &ck.powers_of_g,
                    &powers_of_h,
                    &p_comm,
                    &evals,
                    &share_domain,
                )
                .unwrap());
            let evals_commit =
                g1_commit::<Curve>(&ck.powers_of_g, &poly).unwrap();
            let s_commit =
                g2_commit::<Curve>(&powers_of_h, &share_domain.t.m).unwrap();
            assert!(proof.check_at_domain_with_commitments(
                &powers_of_h,
                &p_comm,
                &s_commit,
                &evals_commit,
            ));
        }
    }
}
