use crate::subproductdomain::{
    fast_divide_monic, moduli_from_scalar, poly_from_scalar,
};
use crate::*;
use ark_ec::AffineCurve;
use ark_ec::PairingEngine;
use ark_ec::ProjectiveCurve;
use ark_ff::{FftField, Field, One, PrimeField, Zero};
use ark_poly::{
    polynomial::univariate::DensePolynomial, EvaluationDomain, UVPolynomial,
};
use ark_poly_commit::Polynomial;
use ark_serialize::*;

#[allow(non_snake_case)]
#[derive(CanonicalSerialize, CanonicalDeserialize, Debug, Clone)]
pub struct Proof<E: PairingEngine> {
    pub cm: E::G1Affine,
    pub W: E::G1Affine,
    pub W_prime: E::G1Affine,
    pub g_evals: Vec<E::G1Affine>,
}

#[allow(non_snake_case)]
impl<E: PairingEngine> Proof<E> {
    pub fn commit_and_open(
        p: &DensePolynomial<E::Fr>,
        domain: &[E::Fr], // Domain of evaluations of p
        evals: &[E::Fr],  // Evaluations of p
        powers_of_g: &[E::G1Affine],
    ) -> Result<Self, anyhow::Error> {
        use ark_ec::msm::FixedBaseMSM;
        use ark_ec::AffineCurve;
        use ark_ec::ProjectiveCurve;

        let g = powers_of_g[0].into_projective();

        let window_size = FixedBaseMSM::get_mul_window_size(p.degree() + 1);
        let scalar_bits = E::Fr::size_in_bits();
        let g_table =
            FixedBaseMSM::get_window_table(scalar_bits, window_size, g);
        let g_evals = FixedBaseMSM::multi_scalar_mul::<E::G1Projective>(
            scalar_bits,
            window_size,
            &g_table,
            evals,
        ); // TODO: is this side-channel safe?

        let g_evals =
            E::G1Projective::batch_normalization_into_affine(&g_evals);

        let moduli = domain
            .iter()
            .map(|r| moduli_from_scalar(r))
            .collect::<Vec<_>>();

        // compute ({ Z_{T/S_i} }, Z_T )
        let (subproducts, Z_T) = compute_subproducts(&moduli);
        let gamma = E::Fr::one(); //TODO: choose a random value
        let mut gamma_i = E::Fr::one(); // gamma^0

        let mut f = DensePolynomial::<E::Fr> { coeffs: vec![] };
        let mut L = DensePolynomial::<E::Fr> { coeffs: vec![] };

        let z = E::Fr::one(); //TODO: choose a random value

        for ((r, Z_S_i), z_i) in
            evals.iter().zip(subproducts.iter()).zip(domain.iter())
        {
            let mut gamma_Z_S_i = Z_S_i.clone();
            for a_i in gamma_Z_S_i.coeffs.iter_mut() {
                // compute gamma^{i-1} * Z_{T/S_i}
                *a_i *= gamma_i;
            }
            for i in domain.iter() {
                if *i != *z_i {
                    assert_eq!(gamma_Z_S_i.evaluate(i), E::Fr::zero());
                }
            }
            let gamma_Z_S_i_at_z = gamma_Z_S_i.evaluate(&z);
            let mut tmp = p.clone();
            tmp.coeffs[0] -= r; // p - r_i
            assert_eq!(tmp.evaluate(&z_i), E::Fr::zero());
            f += &(&gamma_Z_S_i * &tmp); // f += gamma^{i-1} * Z_{T/S_i} * (p - r_i)
            for a_i in tmp.coeffs.iter_mut() {
                *a_i *= gamma_Z_S_i_at_z;
            }
            L += &tmp; // L += gamma^{i-1} * Z_{T/S_i}(z) * (p - r_i)

            gamma_i *= gamma;
        }

        let (mut f_over_Z_T, _r) = fast_divide_monic(&f, &Z_T);
        dbg!(_r);
        let W = crate::fastkzg::g1_commit::<E>(powers_of_g, &f_over_Z_T)?;

        let Z_T_at_z = Z_T.evaluate(&z);

        for a_i in f_over_Z_T.coeffs.iter_mut() {
            // multiply f/Z_t by Z_T(z)
            *a_i *= Z_T_at_z;
        }
        L -= &f_over_Z_T; // subtract Z_T(z) * f/Z_t

        let (L_x_z, _r) = fast_divide_monic(&L, &moduli_from_scalar(&z)); // compute L(x)/(x-z)
        dbg!(_r);
        let W_prime = crate::fastkzg::g1_commit::<E>(powers_of_g, &L_x_z)?;
        Ok(Proof::<E> {
            cm: crate::fastkzg::g1_commit::<E>(powers_of_g, p)?,
            W,
            W_prime,
            g_evals,
        })
    }
    pub fn check(
        &self,
        domain: &[E::Fr], // Domain of evaluations of p
        h: &E::G2Affine,
        beta_h: &E::G2Affine,
    ) -> bool {
        let z = E::Fr::one(); //TODO: choose a random value
        let gamma = E::Fr::one(); // TODO: choose a random value

        let moduli_evals = domain.iter().map(|r| z - *r).collect::<Vec<_>>();

        let (subproducts, Z_T) = compute_subproduct_evaluation(&moduli_evals);

        let mut F = self.W.into_projective();
        F *= -Z_T;

        let mut gamma_i = E::Fr::one();

        let cm = self.cm.into_projective();
        for (r, Z_S_i) in self.g_evals.iter().zip(subproducts.iter()) {
            let mut cm_r = cm - r.into_projective();
            cm_r *= gamma_i * Z_S_i;
            F += cm_r;
            gamma_i *= gamma;
        }
        let mut zW_prime = self.W_prime.into_projective();
        zW_prime *= z;

        // Error in BDFG20 paper; it should be F+zW' instead of F-zW'
        E::pairing(F + zW_prime, *h) == E::pairing(self.W_prime, *beta_h)
    }
}

/// on input T = {(x-a_i)}, compute both the product Z_T = (x-a_n)*...*(x-a_2)*(x-a_1)
/// as well as the subproducts Z_{T/S_i} = (x-a_n)*...*(x-a_2), (x-a_n)*...*(x-a_3)*(x-a_1), ..., (x-a_{n-1})*...*(x-a_1)
pub fn compute_subproducts<F: FftField>(
    moduli: &[DensePolynomial<F>],
) -> (Vec<DensePolynomial<F>>, DensePolynomial<F>) {
    let n = moduli.len();
    let mut partials = Vec::with_capacity(n); // 1, (x-a_n), (x-a_n)(x-a_{n-1}), ..., (x-a_n)*...*(x-a_2)

    let mut z_rev = DensePolynomial::<F> {
        coeffs: vec![F::one()],
    };
    for m in moduli.iter().rev() {
        partials.push(z_rev.clone());
        z_rev = &z_rev * m;
    }

    let mut Z_T = DensePolynomial::<F> {
        coeffs: vec![F::one()],
    };

    let mut missing_one = Vec::with_capacity(n); // (x-a_n)*...*(x-a_2), (x-a_n)*...*(x-a_3)*(x-a_1), ..., (x-a_{n-1})*...*(x-a_1)
    for (m, i) in moduli.iter().zip(partials.iter().rev()) {
        let j = i * &Z_T;
        missing_one.push(j);
        Z_T = &Z_T * m;
    }
    (missing_one, Z_T)
}

/// on input T = {(z-a_i)}, compute both the product Z_T(z) = (z-a_n)*...*(z-a_2)*(z-a_1)
/// as well as the subproducts Z_{T/S_i}(z) = (z-a_n)*...*(z-a_2), (z-a_n)*...*(z-a_3)*(z-a_1), ..., (z-a_{n-1})*...*(z-a_1)
pub fn compute_subproduct_evaluation<F: FftField>(
    moduli_evals: &[F],
) -> (Vec<F>, F) {
    let n = moduli_evals.len();
    let mut partials = Vec::with_capacity(n); // 1, (z-a_n), (z-a_n)(z-a_{n-1}), ..., (z-a_n)*...*(z-a_2)

    let mut z_rev = F::one();
    for m in moduli_evals.iter().rev() {
        partials.push(z_rev);
        z_rev *= *m;
    }

    let mut Z_T = F::one();

    let mut missing_one = Vec::with_capacity(n); // (z-a_n)*...*(z-a_2), (z-a_n)*...*(z-a_3)*(z-a_1), ..., (z-a_{n-1})*...*(z-a_1)
    for (m, i) in moduli_evals.iter().zip(partials.iter().rev()) {
        let j = *i * Z_T;
        missing_one.push(j);
        Z_T *= *m;
    }
    (missing_one, Z_T)
}

#[test]
fn test_bdfg() {
    use ark_poly_commit::Polynomial;
    let rng = &mut ark_std::test_rng();
    let degree = 320usize;
    let domain =
        ark_poly::Radix2EvaluationDomain::<Scalar>::new(2 * degree).unwrap();
    let domain = (160u64..481u64)
        .map(|i| domain.group_gen.pow(&[i]))
        .collect::<Vec<_>>();
    let pp = KZG::setup(degree, false, rng).unwrap();
    let (ck, vk) = crate::fastkzg::trim(&pp, degree).unwrap();

    for _ in 0..10 {
        let p = DensePolynomial::<Scalar>::rand(degree as usize, rng);
        let eval = p.evaluate(&domain[0]);
        let proof = Proof::<Curve>::commit_and_open(
            &p,
            &[domain[0]],
            &[eval],
            &ck.powers_of_g,
        )
        .unwrap();
        assert!(proof.check(&[domain[0]], &vk.h, &vk.beta_h));
    }

    for _ in 0..10 {
        let p = DensePolynomial::<Scalar>::rand(degree as usize, rng);
        let evals = domain.iter().map(|x| p.evaluate(x)).collect::<Vec<_>>();

        let proof = Proof::<Curve>::commit_and_open(
            &p,
            &domain,
            &evals,
            &ck.powers_of_g,
        )
        .unwrap();

        assert!(proof.check(&domain, &vk.h, &vk.beta_h));
    }
}
#[test]
fn test_subproduct_evaluation() {
    use ark_poly_commit::Polynomial;
    let rng = &mut ark_std::test_rng();
    use ark_std::UniformRand;
    let degree = 320usize;
    let domain =
        ark_poly::Radix2EvaluationDomain::<Scalar>::new(2 * degree).unwrap();
    let domain = (160u64..481u64)
        .map(|i| domain.group_gen.pow(&[i]))
        .collect::<Vec<_>>();

    let moduli = domain
        .iter()
        .map(|r| moduli_from_scalar(r))
        .collect::<Vec<_>>();

    let (missing_one, Z_T) = compute_subproducts(&moduli);

    let mut other_Z_T = DensePolynomial::<Scalar> {
        coeffs: vec![Scalar::one()],
    };
    for m in moduli.iter() {
        other_Z_T = &other_Z_T * m;
    }

    let z = Scalar::rand(rng); //TODO: choose a random value

    let moduli_evals = domain.iter().map(|r| z - *r).collect::<Vec<_>>();
    let (missing_one_eval, Z_T_eval) =
        compute_subproduct_evaluation(&moduli_evals);

    assert_eq!(Z_T.evaluate(&z), Z_T_eval);
    assert_eq!(other_Z_T.evaluate(&z), Z_T_eval);

    for ((i, j), m) in missing_one
        .iter()
        .zip(missing_one_eval.iter())
        .zip(moduli.iter())
    {
        let eval = i.evaluate(&z);
        assert_eq!(eval, *j);

        let (q, _) = crate::subproductdomain::fast_divide_monic(&other_Z_T, &m);
        assert_eq!(eval, q.evaluate(&z));
    }
}

#[test]
fn direct() {
    use ark_poly_commit::Polynomial;
    let rng = &mut ark_std::test_rng();
    let degree = 320u32;
    for _ in 0..1 {
        let p = DensePolynomial::<Scalar>::rand(degree as usize, rng);

        let evals = (0u32..degree + 1)
            .map(|x| p.evaluate(&Scalar::from(x)))
            .collect::<Vec<Scalar>>();

        let moduli = evals
            .iter()
            .map(|y| DensePolynomial::<Scalar> {
                coeffs: vec![-*y, Scalar::one()], //todo negate y
            })
            .collect::<Vec<DensePolynomial<Scalar>>>();

        let mut v = DensePolynomial::<Scalar> {
            coeffs: vec![Scalar::one()],
        };

        for (excluded, r) in moduli.iter().zip(evals.iter()) {
            let mut z = DensePolynomial::<Scalar> {
                coeffs: vec![Scalar::one()],
            };
            for m in moduli.iter() {
                if m != excluded {
                    z = &z * &m;
                }
            }
            let mut p = p.clone();
            p.coeffs[0] -= r;
            z = &z * &p;
            //todo add gamma
            v += &z;
        }
        let mut z = DensePolynomial::<Scalar> {
            coeffs: vec![Scalar::one()],
        };
        for m in moduli.iter() {
            z = &z * &m;
        }
        crate::subproductdomain::fast_divide_monic(&v, &z);
    }
}

#[test]
fn indirect() {
    use ark_poly_commit::Polynomial;
    let rng = &mut ark_std::test_rng();
    let degree = 320u32;
    for _ in 0..1 {
        let p = DensePolynomial::<Scalar>::rand(degree as usize, rng);

        let evals = (0u32..degree + 1)
            .map(|x| p.evaluate(&Scalar::from(x)))
            .collect::<Vec<Scalar>>();

        let moduli = evals
            .iter()
            .map(|y| DensePolynomial::<Scalar> {
                coeffs: vec![-*y, Scalar::one()], //todo negate y
            })
            .collect::<Vec<DensePolynomial<Scalar>>>();

        let mut v = DensePolynomial::<Scalar> {
            coeffs: vec![Scalar::one()],
        };

        for (m, r) in moduli.iter().zip(evals.iter()) {
            let mut p = p.clone();
            p.coeffs[0] -= r;

            //todo add gamma
            v += &crate::subproductdomain::fast_divide_monic(&p, &m).0;
        }
    }
}

#[test]
fn batchdivide() {
    use ark_poly_commit::Polynomial;
    let rng = &mut ark_std::test_rng();
    let degree = 320u32;
    for _ in 0..1 {
        let p = DensePolynomial::<Scalar>::rand(degree as usize, rng);

        let evals = (0u32..degree + 1)
            .map(|x| p.evaluate(&Scalar::from(x)))
            .collect::<Vec<Scalar>>();

        let moduli = evals
            .iter()
            .map(|y| DensePolynomial::<Scalar> {
                coeffs: vec![-*y, Scalar::one()], //todo negate y
            })
            .collect::<Vec<DensePolynomial<Scalar>>>();

        let mut v = DensePolynomial::<Scalar> {
            coeffs: vec![Scalar::one()],
        };

        let mut z = DensePolynomial::<Scalar> {
            coeffs: vec![Scalar::one()],
        };
        for m in moduli.iter() {
            z = &z * m;
        }

        for (excluded, r) in moduli.iter().zip(evals.iter()) {
            let (q, _) =
                crate::subproductdomain::fast_divide_monic(&z, &excluded);
            let mut p = p.clone();
            p.coeffs[0] -= r;
            let q = &q * &p;
            //todo add gamma
            v += &q;
        }
    }
}

#[test]
fn dynamic() {
    use ark_poly_commit::Polynomial;
    let rng = &mut ark_std::test_rng();
    let degree = 320u32;
    for _ in 0..1 {
        let p = DensePolynomial::<Scalar>::rand(degree as usize, rng);

        let evals = (0u32..degree + 1)
            .map(|x| p.evaluate(&Scalar::from(x)))
            .collect::<Vec<Scalar>>();

        let moduli = evals
            .iter()
            .map(|y| DensePolynomial::<Scalar> {
                coeffs: vec![-*y, Scalar::one()], //todo negate y
            })
            .collect::<Vec<DensePolynomial<Scalar>>>();

        let mut partials = vec![];

        let mut z = DensePolynomial::<Scalar> {
            coeffs: vec![Scalar::one()],
        };
        for m in moduli.iter() {
            partials.push(z.clone());
            z = &z * m;
        }

        let mut z_prime = DensePolynomial::<Scalar> {
            coeffs: vec![Scalar::one()],
        };

        let mut missing_one = vec![];
        for (m, i) in moduli.iter().zip(partials.iter()).rev() {
            let j = i * &z_prime;
            missing_one.push(j);
            z_prime = &z_prime * m;
        }

        let mut v = DensePolynomial::<Scalar> {
            coeffs: vec![Scalar::one()],
        };
        for (excluded, r) in missing_one.iter().rev().zip(evals.iter()) {
            let mut p = p.clone();
            p.coeffs[0] -= r;
            let q = excluded * &p;
            //todo add gamma
            v += &q;
        }
        crate::subproductdomain::fast_divide_monic(&v, &z);
    }
}
