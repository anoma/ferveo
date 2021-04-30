use ark_bls12_381::{
    Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ark_ff::{Field, One, Zero};
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, UVPolynomial};
use ark_poly_commit::kzg10::{
    Commitment, Powers, UniversalParams, VerifierKey, KZG10,
};

pub fn open_amortized(
    powers: &Powers<Bls12_381>,
    polynomial: &DensePolynomial<Fr>,
    n: usize,
) -> Result<Vec<G1Projective>, anyhow::Error> {
    //use ark_ec::AffineCurve;
    let m = polynomial.coeffs.len() - 1;
    let domain = ark_poly::Radix2EvaluationDomain::<Fr>::new(1 << n)
        .ok_or_else(|| anyhow::anyhow!("bad domain"))?;
    let mut p = powers.powers_of_g[0..m].to_vec();
    let mut h = toeplitz_mul(polynomial, &p, domain.size())?;

    ec_fft(&mut h, domain.group_gen, domain.log_size_of_group);

    Ok(h)
}

pub fn open_amortized_unnormalized(
    powers: &Powers<Bls12_381>,
    polynomial: &DensePolynomial<Fr>,
    n: usize,
) -> Result<(Vec<G1Projective>, Fr), anyhow::Error> {
    //use ark_ec::AffineCurve;
    let m = polynomial.coeffs.len() - 1;
    let domain = ark_poly::Radix2EvaluationDomain::<Fr>::new(1 << n)
        .ok_or_else(|| anyhow::anyhow!("bad domain"))?;
    let mut p = powers.powers_of_g[0..m].to_vec();
    let (mut h, domain_size_inv) =
        toeplitz_mul_unnormalized(polynomial, &p, domain.size())?;

    ec_fft(&mut h, domain.group_gen, domain.log_size_of_group);

    Ok((h, domain_size_inv))
}

pub fn build_circulant(
    polynomial: &DensePolynomial<Fr>,
    size: usize,
) -> Vec<Fr> {
    let mut circulant = vec![Fr::zero(); 2 * size];
    let coeffs = polynomial.coeffs();
    if size == coeffs.len() - 1 {
        circulant[0] = *coeffs.last().unwrap();
        circulant[size] = *coeffs.last().unwrap();
        circulant[size + 1..size + 1 + coeffs.len() - 2]
            .copy_from_slice(&coeffs[1..coeffs.len() - 1]);
    } else {
        circulant[size + 1..size + 1 + coeffs.len() - 1]
            .copy_from_slice(&coeffs[1..]);
    }
    circulant
}

pub fn toeplitz_mul(
    polynomial: &DensePolynomial<Fr>,
    v: &[G1Affine],
    size: usize,
) -> Result<Vec<G1Projective>, anyhow::Error> {
    use ark_ec::AffineCurve;

    let m = polynomial.coeffs.len() - 1;
    let size = ark_std::cmp::max(size, m);

    let domain = ark_poly::Radix2EvaluationDomain::<Fr>::new(2 * size)
        .ok_or_else(|| anyhow::anyhow!("bad domain"))?;

    let size = domain.size() / 2;
    let mut circulant = build_circulant(&polynomial, size);

    let mut tmp: Vec<G1Projective> = Vec::with_capacity(domain.size());

    for _ in 0..(size - v.len()) {
        tmp.push(G1Projective::zero());
    }

    for i in v.iter().rev() {
        tmp.push(i.into_projective());
    }

    tmp.resize(domain.size(), G1Projective::zero());
    ec_fft(&mut tmp, domain.group_gen, domain.log_size_of_group);
    domain.fft_in_place(&mut circulant);

    for (i, j) in tmp.iter_mut().zip(circulant.iter()) {
        *i *= *j;
    }

    ec_fft(&mut tmp, domain.group_gen_inv, domain.log_size_of_group);
    let domain_size_inv = Fr::from(domain.size() as u64).inverse().unwrap();
    for p in tmp.iter_mut() {
        *p *= domain_size_inv;
    }

    Ok(tmp[..size].to_vec())
}

pub fn toeplitz_mul_unnormalized(
    polynomial: &DensePolynomial<Fr>,
    v: &[G1Affine],
    size: usize,
) -> Result<(Vec<G1Projective>, Fr), anyhow::Error> {
    use ark_ec::AffineCurve;

    let m = polynomial.coeffs.len() - 1;
    let size = ark_std::cmp::max(size, m);

    let domain = ark_poly::Radix2EvaluationDomain::<Fr>::new(2 * size)
        .ok_or_else(|| anyhow::anyhow!("bad domain"))?;

    let size = domain.size() / 2;
    let mut circulant = build_circulant(&polynomial, size);

    let mut tmp: Vec<G1Projective> = Vec::with_capacity(domain.size());

    for _ in 0..(size - v.len()) {
        tmp.push(G1Projective::zero());
    }

    for i in v.iter().rev() {
        tmp.push(i.into_projective());
    }

    tmp.resize(domain.size(), G1Projective::zero());
    ec_fft(&mut tmp, domain.group_gen, domain.log_size_of_group);
    domain.fft_in_place(&mut circulant);

    for (i, j) in tmp.iter_mut().zip(circulant.iter()) {
        *i *= *j;
    }

    ec_fft(&mut tmp, domain.group_gen_inv, domain.log_size_of_group);

    Ok((
        tmp[..size].to_vec(),
        Fr::from(domain.size() as u64).inverse().unwrap(),
    ))
}

pub fn ec_fft(a: &mut [G1Projective], omega: Fr, two_adicity: u32) {
    let n = a.len();
    assert_eq!(n, 1 << two_adicity);

    // swapping in place (from Storer's book)
    for k in 0..n {
        let rk = bitreverse(k as u32, two_adicity) as usize;
        if k < rk {
            a.swap(k, rk);
        }
    }

    let mut m = 1;
    for _ in 0..two_adicity {
        // w_m is 2^s-th root of unity now
        let w_m = omega.pow(&[(n / (2 * m)) as u64]);

        let mut k = 0;
        while k < n {
            let mut w = Fr::one();
            for j in 0..m {
                let mut t = a[(k + m) + j];
                t *= w;
                a[(k + m) + j] = a[k + j];
                a[(k + m) + j] -= t;
                a[k + j] += t;
                w *= w_m;
            }
            k += 2 * m;
        }
        m *= 2;
    }
}

#[inline]
pub(crate) fn bitreverse(mut n: u32, l: u32) -> u32 {
    let mut r = 0;
    for _ in 0..l {
        r = (r << 1) | (n & 1);
        n >>= 1;
    }
    r
}

pub fn trim(
    pp: &UniversalParams<Bls12_381>,
    mut supported_degree: usize,
) -> (Powers<Bls12_381>, VerifierKey<Bls12_381>) {
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
    (powers, vk)
}

pub fn compute_ai(p: &[Fr]) -> DensePolynomial<Fr> {
    //todo: zero length case?
    let mut subproduct_tree = p
        .iter()
        .map(|p| {
            DensePolynomial::<Fr>::from_coefficients_slice(&[-*p, Fr::one()])
        })
        .collect::<std::collections::VecDeque<DensePolynomial<Fr>>>();

    loop {
        if subproduct_tree.len() == 1 {
            return subproduct_tree.pop_front().unwrap();
        }
        let a = subproduct_tree.pop_front().unwrap();
        let b = subproduct_tree.pop_front().unwrap();
        subproduct_tree.push_back(&a * &b);
    }
}

pub fn lagrange_interpolate(
    share_domain: &[Fr],
    values: &[Fr],
    A_I: &DensePolynomial<Fr>,
    A_I_prime: &DensePolynomial<Fr>,
) -> DensePolynomial<Fr> {
    use ark_poly::Polynomial;
    //use std::ops::Mul;
    let mut total = DensePolynomial::<Fr> {
        coeffs: Vec::<Fr>::with_capacity(values.len()),
    };
    for (i, z) in share_domain.iter().zip(values.iter()) {
        let mut t = A_I
            / &DensePolynomial::<Fr>::from_coefficients_slice(&[
                -*i,
                Fr::one(),
            ]);
        //let t = &t * *z; //TODO: doesn't work?
        for c in t.coeffs.iter_mut() {
            *c *= *z / A_I_prime.evaluate(i);
        }
        total = total + t;
    }
    total
}

pub fn compute_ci(
    share_domain: &[Fr],
    A_I_prime: &DensePolynomial<Fr>,
) -> Vec<Fr> {
    use ark_poly::Polynomial;
    //let A_I = compute_ai(&share_domain);
    //let A_I_prime = A_I.derivative();
    share_domain
        .iter()
        .map(|p| A_I_prime.evaluate(p).inverse().unwrap()) //TODO: better handle inverse.unwrap()
        .collect() //TODO: FFT approach
}

pub fn batch_proofs(ci: &[Fr], proofs: &[G1Projective]) -> G1Projective {
    use ark_ec::group::Group;
    let mut total = G1Projective::zero();
    for (c, proof) in ci.iter().zip(proofs.iter()) {
        total += proof.mul(c);
    }
    total
}

/// Verifies that `value` is the evaluation at `point` of the polynomial
/// committed inside `comm`.
pub fn check_batched(
    powers_of_h: &[G2Affine],
    ck: &Powers<Bls12_381>,
    vk: &VerifierKey<Bls12_381>,
    comm: &Commitment<Bls12_381>,
    //share_domain: &[Fr],
    A_I: &DensePolynomial<Fr>,
    evaluation_polynomial: &DensePolynomial<Fr>,
    //value: &[Fr],
    proof: &G1Affine,
) -> Result<bool, anyhow::Error> {
    use ark_ec::AffineCurve;
    use ark_ec::PairingEngine;
    //let check_time = start_timer!(|| "Checking evaluation");
    let mut inner = comm.0.into_projective()
        - KZG10::commit(ck, evaluation_polynomial, None, None)?
            .0
             .0
            .into_projective(); //&vk.g.mul(value);
                                //if let Some(random_v) = proof.random_v {
                                //    inner -= &vk.gamma_g.mul(random_v);
                                //}
    let lhs = Bls12_381::pairing(inner, vk.h);

    let inner = g2_commit(powers_of_h, A_I)?.into_projective(); //vk.beta_h.into_projective() - &vk.h.mul(point);
    let rhs = Bls12_381::pairing(*proof, inner);

    //end_timer!(check_time, || format!("Result: {}", lhs == rhs));
    Ok(lhs == rhs)
}

use crate::fastpoly::derivative;
/*pub fn derivative(p: &DensePolynomial<Fr>) -> DensePolynomial<Fr> {
    let mut coeffs = Vec::with_capacity(p.coeffs.len() - 1);
    for (i, c) in p.coeffs.iter().enumerate().skip(1) {
        coeffs.push(Fr::from(i as u64) * c);
    }
    DensePolynomial::<Fr> { coeffs }
}*/

pub fn g2_commit(
    powers_of_h: &[G2Affine],
    polynomial: &DensePolynomial<Fr>,
) -> Result<G2Affine, anyhow::Error> {
    use ark_ec::msm::VariableBaseMSM;
    //TODO: check degree is a private
    /*Self::check_degree_is_too_large(
        polynomial.degree(),
        powers.size(),
    )?;*/

    let (num_leading_zeros, plain_coeffs) =
        skip_leading_zeros_and_convert_to_bigints(polynomial);

    let mut commitment = VariableBaseMSM::multi_scalar_mul(
        &powers_of_h[num_leading_zeros..],
        &plain_coeffs,
    );
    Ok(commitment.into())
}

pub fn setup<R: rand::RngCore>(
    max_degree: usize,
    rng: &mut R,
) -> Result<(UniversalParams<Bls12_381>, Vec<G2Affine>), anyhow::Error> {
    use ark_ec::group::Group;
    use ark_ec::msm::FixedBaseMSM;
    use ark_ec::AffineCurve;
    use ark_ec::ProjectiveCurve;
    use ark_ff::PrimeField;
    use ark_std::UniformRand;
    if max_degree < 1 {
        return Err(anyhow::anyhow!("DegreeIsZero"));
    }
    let beta = Fr::rand(rng);
    let g = G1Projective::rand(rng);
    let gamma_g = G1Projective::rand(rng);
    let h = G2Projective::rand(rng);

    let mut powers_of_beta = vec![Fr::one()];

    let mut cur = beta;
    for _ in 0..max_degree {
        powers_of_beta.push(cur);
        cur *= &beta;
    }

    let window_size = FixedBaseMSM::get_mul_window_size(max_degree + 1);

    let scalar_bits = Fr::size_in_bits();
    let g_table = FixedBaseMSM::get_window_table(scalar_bits, window_size, g);
    let powers_of_g = FixedBaseMSM::multi_scalar_mul::<G1Projective>(
        scalar_bits,
        window_size,
        &g_table,
        &powers_of_beta,
    );

    let h_table = FixedBaseMSM::get_window_table(scalar_bits, window_size, h);
    let powers_of_h = FixedBaseMSM::multi_scalar_mul::<G2Projective>(
        scalar_bits,
        window_size,
        &h_table,
        &powers_of_beta,
    );

    let gamma_g_table =
        FixedBaseMSM::get_window_table(scalar_bits, window_size, gamma_g);
    let mut powers_of_gamma_g = FixedBaseMSM::multi_scalar_mul::<G1Projective>(
        scalar_bits,
        window_size,
        &gamma_g_table,
        &powers_of_beta,
    );
    // Add an additional power of gamma_g, because we want to be able to support
    // up to D queries.
    powers_of_gamma_g.push(powers_of_gamma_g.last().unwrap().mul(&beta));

    let powers_of_g =
        G1Projective::batch_normalization_into_affine(&powers_of_g);

    let powers_of_h =
        G2Projective::batch_normalization_into_affine(&powers_of_h);
    let powers_of_gamma_g =
        G1Projective::batch_normalization_into_affine(&powers_of_gamma_g)
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
fn skip_leading_zeros_and_convert_to_bigints(
    p: &DensePolynomial<Fr>,
) -> (usize, Vec<<Fr as ark_ff::PrimeField>::BigInt>) {
    let mut num_leading_zeros = 0;
    while num_leading_zeros < p.coeffs().len()
        && p.coeffs()[num_leading_zeros].is_zero()
    {
        num_leading_zeros += 1;
    }
    let coeffs = convert_to_bigints(&p.coeffs()[num_leading_zeros..]);
    (num_leading_zeros, coeffs)
}

fn convert_to_bigints(p: &[Fr]) -> Vec<<Fr as ark_ff::PrimeField>::BigInt> {
    use ark_ff::PrimeField;
    let coeffs = ark_std::cfg_iter!(p)
        .map(|s| s.into_repr())
        .collect::<Vec<_>>();
    coeffs
}
#[test]
fn test_open() {
    use ark_poly::Polynomial;
    use ark_poly_commit::kzg10::Proof;
    type KZG = KZG10<Bls12_381, DensePolynomial<Fr>>;
    let rng = &mut ark_std::test_rng();

    let n = 9;
    let total_weight = 1 << n;
    {
        let degree = 2 * total_weight / 3;
        let (pp, powers_of_h) = setup(degree, rng).unwrap();
        let (ck, vk) = trim(&pp, degree);

        for _ in 0..10 {
            let p = DensePolynomial::<Fr>::rand(degree, rng);

            let (comm, rand) = KZG::commit(&ck, &p, None, None).unwrap();

            let domain =
                ark_poly::Radix2EvaluationDomain::<Fr>::new(total_weight)
                    .unwrap();

            let openings = open_amortized(&ck, &p, n).unwrap();
            let affine_openings = openings
                .iter()
                .map(|p| (*p).into())
                .collect::<Vec<G1Affine>>();

            let mut point = Fr::one();

            for (k, i) in affine_openings.iter().enumerate() {
                dbg!(k);
                let value = p.evaluate(&point);
                let j = KZG::open(&ck, &p, point, &rand).unwrap();
                assert!(KZG::check(&vk, &comm, point, value, &j).unwrap());
                assert!(KZG::check(
                    &vk,
                    &comm,
                    point,
                    value,
                    &Proof {
                        w: *i,
                        random_v: None
                    }
                )
                .unwrap());
                point *= domain.group_gen;
            }
            let mut share_domain =
                Vec::with_capacity(1 << domain.log_size_of_group);
            let mut t = Fr::one();
            for _ in 0..1 << domain.log_size_of_group {
                share_domain.push(t);
                t *= domain.group_gen;
            }
            let A_I = compute_ai(&share_domain);
            let A_I_prime = derivative(&A_I);
            let c_i = compute_ci(&share_domain, &A_I_prime);
            let batch = batch_proofs(&c_i, &openings);
            assert!(check_batched(
                &powers_of_h,
                &ck,
                &vk,
                &comm,
                &A_I,
                &lagrange_interpolate(
                    &share_domain,
                    &share_domain
                        .iter()
                        .map(|x| p.evaluate(x))
                        .collect::<Vec<Fr>>(),
                    &A_I,
                    &A_I_prime,
                ),
                &batch.into(),
            )
            .unwrap());
        }
    }
}

#[test]
fn test_fft() {
    use ark_ec::group::Group;
    use ark_ec::AffineCurve;
    use ark_std::test_rng;
    let rng = &mut test_rng();
    let mut tmp: Vec<G1Affine> = Vec::with_capacity(128);
    for _ in 0..128 {
        tmp.push(G1Affine::prime_subgroup_generator());
    }

    let mut tmp2 = tmp
        .iter()
        .map(|p| G1Projective::from(*p))
        .collect::<Vec<G1Projective>>();

    let domain =
        ark_poly::Radix2EvaluationDomain::<Fr>::new(tmp.len()).unwrap();

    assert_eq!(domain.size(), tmp.len());

    let mut total = G1Projective::zero();
    let mut omega = Fr::one();
    for i in tmp2.iter() {
        total = total + i.mul(&omega);
        omega = omega * domain.group_gen * domain.group_gen;
    }

    ec_fft(&mut tmp2, domain.group_gen, domain.log_size_of_group);

    for i in tmp2.iter() {
        if G1Affine::from(*i) == G1Affine::from(total) {
            dbg!(i);
        }
    }
    assert_eq!(G1Affine::from(total), G1Affine::from(tmp2[2]));

    ec_fft(&mut tmp2, domain.group_gen_inv, domain.log_size_of_group);
    let domain_size_inv = Fr::from(domain.size() as u64).inverse().unwrap();
    for p in tmp2.iter_mut() {
        *p *= domain_size_inv;
    }

    for (i, j) in tmp.iter().zip(tmp2.iter()) {
        assert_eq!(*i, G1Affine::from(*j));
    }
}

#[test]
fn test_toeplitz() {
    use ark_ec::AffineCurve;
    use ark_poly::Polynomial;
    type KZG = KZG10<Bls12_381, DensePolynomial<Fr>>;
    let rng = &mut ark_std::test_rng();
    for total_weight in 95..130 {
        let degree = 2 * total_weight / 3;

        let pp = KZG::setup(degree, false, rng).unwrap();
        let (ck, vk) = trim(&pp, degree);

        for _ in 0..4 {
            let polynomial = DensePolynomial::<Fr>::rand(degree, rng);

            let coeffs = polynomial.coeffs();
            let m = polynomial.coeffs.len() - 1;

            let domain =
                ark_poly::Radix2EvaluationDomain::<Fr>::new(total_weight)
                    .ok_or_else(|| anyhow::anyhow!("bad domain"))
                    .unwrap();
            let mut p = ck.powers_of_g[0..m].to_vec();
            let h = toeplitz_mul(&polynomial, &p, total_weight).unwrap();

            let h = h.iter().map(|p| (*p).into()).collect::<Vec<G1Affine>>();

            for i in 1..=m {
                let mut total = G1Projective::zero();
                for j in 0..=m - i {
                    total = total + (p[j].mul(coeffs[i + j]));
                }
                assert_eq!(G1Affine::from(total), h[i - 1]);
            }
        }
    }
}

#[test]
fn test_interpolate() {
    use ark_poly::Polynomial;
    use ark_std::UniformRand;
    let rng = &mut ark_std::test_rng();
    let mut points = vec![];
    let mut evals = vec![];
    for _ in 0..100 {
        points.push(Fr::rand(rng));
        evals.push(Fr::rand(rng));
    }

    let A_I = compute_ai(&points);
    let A_I_prime = derivative(&A_I);

    for p1 in points.iter() {
        let mut prod = Fr::one();
        for p2 in points.iter() {
            if *p1 != *p2 {
                prod *= *p1 - p2;
            }
        }
        assert_eq!(A_I_prime.evaluate(p1), prod);
    }

    let p = lagrange_interpolate(&points, &evals, &A_I, &A_I_prime);

    for (x, y) in points.iter().zip(evals.iter()) {
        assert_eq!(A_I.evaluate(x), Fr::zero());
        dbg!(x);
        dbg!(y);
        assert_eq!(p.evaluate(x), *y)
    }
}

#[test]
fn test_all() {
    use crate::fastpoly::*;
    use ark_poly::Polynomial;
    type KZG = KZG10<Bls12_381, DensePolynomial<Fr>>;
    let rng = &mut ark_std::test_rng();

    let n = 10;
    let total_weight = 1 << n;
    {
        let degree = 2 * total_weight / 3;
        let (pp, powers_of_h) = setup(degree, rng).unwrap();
        let (ck, vk) = trim(&pp, degree);

        for _ in 0..1 {
            let p = DensePolynomial::<Fr>::rand(degree, rng);

            let (comm, rand) = KZG::commit(&ck, &p, None, None).unwrap();

            let domain =
                ark_poly::Radix2EvaluationDomain::<Fr>::new(total_weight)
                    .unwrap();

            let openings = open_amortized(&ck, &p, n).unwrap();
            let affine_openings = openings
                .iter()
                .map(|p| (*p).into())
                .collect::<Vec<G1Affine>>();

            let mut point = Fr::one();

            let mut share_domain =
                Vec::with_capacity(1 << domain.log_size_of_group);
            let mut t = Fr::one();
            for _ in 0..1 << domain.log_size_of_group {
                share_domain.push(t);
                t *= domain.group_gen;
            }
            let A_I = subproduct_tree(&share_domain);
            let A_I_prime = derivative(&A_I.M);

            let evals = share_domain
                .iter()
                .map(|x| p.evaluate(x))
                .collect::<Vec<Fr>>();

            let (poly, proof) = fast_interpolate_and_batch(
                &share_domain,
                &evals,
                &openings,
                &A_I,
                None,
            );

            /*for i in share_domain.iter() {
                assert_eq!(A_I.M.evaluate(i), Fr::zero());
            }*/

            assert!(check_batched(
                &powers_of_h,
                &ck,
                &vk,
                &comm,
                &A_I.M,
                &poly,
                &proof.into(),
            )
            .unwrap());
        }
    }
}
