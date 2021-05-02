use ark_bls12_381::{Fr, G1Projective};
use ark_ff::{One, Zero};
use ark_poly::polynomial::univariate::DensePolynomial;

pub fn inverse_mod_xl(
    f: &DensePolynomial<Fr>,
    l: usize,
) -> Option<DensePolynomial<Fr>> {
    use ark_ff::Field;
    //use std::ops::Mul;
    //let r =
    //    std::mem::size_of::<u64>() * 8 - (l as u64).leading_zeros() as usize; // ceil(log_2(l))

    //assert_eq!((l as f64).log2().ceil() as usize, r);
    let r = (l as f64).log2().ceil() as usize; //TODO: rounding problems??
    let mut g = DensePolynomial::<Fr> {
        coeffs: vec![f.coeffs[0].inverse().unwrap()], //todo unwrap
    };
    let mut i = 2usize;
    for _ in 0..r {
        g = &(&g + &g) - &(f * &(&g * &g)); //todo: g*2?
                                            //g = modulo_xl(&g, i);
                                            //g = modulo_xl(&g, i);
        g.coeffs.resize(i, Fr::zero());
        i *= 2;
    }
    Some(g)
}

pub fn rev(f: &mut DensePolynomial<Fr>, m: usize) {
    assert!(f.coeffs.len() - 1 <= m);
    for _ in 0..(m - (f.coeffs.len() - 1)) {
        f.coeffs.push(Fr::zero());
    }
    f.reverse();
}

pub fn fast_divide_monic(
    f: &DensePolynomial<Fr>,
    g: &DensePolynomial<Fr>,
) -> (DensePolynomial<Fr>, DensePolynomial<Fr>) {
    if f.coeffs.len() < g.coeffs.len() {
        return (
            DensePolynomial::<Fr> {
                coeffs: vec![Fr::zero()],
            },
            f.clone(),
        );
    }
    let m = f.coeffs.len() - g.coeffs.len();

    let mut rev_f = f.clone();
    let mut rev_g = g.clone();
    rev_f.reverse();
    rev_g.reverse();

    let mut q = &rev_f * &inverse_mod_xl(&rev_g, m + 1).unwrap();
    q.coeffs.resize(m + 1, Fr::zero());
    rev(&mut q, m);
    let r = f - &(g * &q);
    (q, r)
}

#[derive(Debug, Clone)]
pub struct SubproductTree {
    pub left: Option<Box<SubproductTree>>,
    pub right: Option<Box<SubproductTree>>,
    pub M: DensePolynomial<Fr>,
}

pub fn subproduct_tree(u: &[Fr]) -> SubproductTree {
    if u.len() == 1 {
        SubproductTree {
            left: None,
            right: None,
            M: DensePolynomial::<Fr> {
                coeffs: vec![-u[0], Fr::one()],
            },
        }
    } else {
        let n = u.len() / 2;
        let (u_0, u_1) = u.split_at(n);
        let left = Box::new(subproduct_tree(u_0));
        let right = Box::new(subproduct_tree(u_1));
        let M = &left.M * &right.M;
        SubproductTree {
            left: Some(left),
            right: Some(right),
            M,
        }
    }
}

pub fn fast_evaluate(
    f: &DensePolynomial<Fr>,
    u: &[Fr],
    s: &SubproductTree,
    t: &mut [Fr],
) {
    //todo: assert degree < u.len()
    if u.len() == 1 {
        t[0] = f.coeffs[0];
        return;
    }

    let left = s.left.as_ref().unwrap();
    let right = s.right.as_ref().unwrap();

    let (q_0, r_0) = fast_divide_monic(f, &left.M);
    let (_, r_1) = fast_divide_monic(f, &right.M);

    let n = u.len() / 2;
    let (u_0, u_1) = u.split_at(n);
    let (t_0, t_1) = t.split_at_mut(n);

    fast_evaluate(&r_0, u_0, &left, t_0);
    fast_evaluate(&r_1, u_1, &right, t_1);
}

pub fn fast_interpolate(
    u: &[Fr],
    v: &[Fr],
    s: &SubproductTree,
) -> DensePolynomial<Fr> {
    use ark_ff::Field;
    let mut lagrange_coeff = fast_inverse_lagrange_coefficients(u, s);

    for (s_i, v_i) in lagrange_coeff.iter_mut().zip(v.iter()) {
        *s_i = s_i.inverse().unwrap() * *v_i;
    }

    fast_linear_combine(u, &lagrange_coeff, &s)
}

pub fn fast_inverse_lagrange_coefficients(
    u: &[Fr],
    s: &SubproductTree,
) -> Vec<Fr> {
    //assert u.len() == degree of s.M
    if u.len() == 1 {
        return vec![Fr::one()];
    }
    let mut evals = vec![Fr::zero(); u.len()];
    let m_prime = derivative(&s.M);
    fast_evaluate(&m_prime, u, s, &mut evals);
    evals
}

pub fn fast_interpolate_and_batch(
    u: &[Fr],
    v: &[Fr],
    points: &[G1Projective],
    s: &SubproductTree,
    normalize: Option<Fr>,
) -> (DensePolynomial<Fr>, G1Projective) {
    use ark_ff::Field;
    let mut lagrange_coeff = fast_inverse_lagrange_coefficients(u, s);

    let mut c = lagrange_coeff
        .iter()
        .map(|x| x.inverse().unwrap())
        .collect::<Vec<Fr>>();

    use ark_ec::group::Group;
    let mut total = G1Projective::zero();
    for (c_i, point) in c.iter().zip(points.iter()) {
        if let Some(norm) = normalize {
            total += point.mul(&(norm * c_i));
        } else {
            total += point.mul(c_i);
        }
    }

    for (s_i, v_i) in c.iter_mut().zip(v.iter()) {
        *s_i = *s_i * v_i;
    }

    (fast_linear_combine(u, &c, &s), total)
}

pub fn derivative(p: &DensePolynomial<Fr>) -> DensePolynomial<Fr> {
    let mut coeffs = Vec::with_capacity(p.coeffs.len() - 1);
    for (i, c) in p.coeffs.iter().enumerate().skip(1) {
        coeffs.push(Fr::from(i as u64) * c);
    }
    DensePolynomial::<Fr> { coeffs }
}

pub fn fast_linear_combine(
    u: &[Fr],
    c: &[Fr],
    s: &SubproductTree,
) -> DensePolynomial<Fr> {
    if u.len() == 1 {
        return DensePolynomial::<Fr> { coeffs: vec![c[0]] };
    }
    let n = u.len() / 2;
    let (u_0, u_1) = u.split_at(n);
    let (c_0, c_1) = c.split_at(n);

    let left = s.left.as_ref().unwrap();
    let right = s.right.as_ref().unwrap();
    let r_0 = fast_linear_combine(u_0, c_0, left);
    let r_1 = fast_linear_combine(u_1, c_1, right);

    &(&right.M * &r_0) + &(&left.M * &r_1)
}
#[cfg(test)]
mod tests {
    use crate::fastpoly::*;
    use ark_ff::Field;
    use ark_poly::Polynomial;
    use ark_poly_commit::UVPolynomial;
    use ark_std::UniformRand;

    #[test]
    fn test_inverse() {
        let rng = &mut ark_std::test_rng();

        let degree = 100;
        let l = 101;
        for _ in 0..100 {
            let p = DensePolynomial::<Fr>::rand(degree, rng);
            let p_inv = inverse_mod_xl(&p, l).unwrap();
            let mut t = &p * &p_inv;
            t.coeffs.resize(l, Fr::zero());
            assert_eq!(t.coeffs[0], Fr::one());
            for i in t.iter().skip(1) {
                assert_eq!(*i, Fr::zero());
            }
        }
    }

    #[test]
    fn test_divide() {
        let rng = &mut ark_std::test_rng();

        let degree = 100;
        let l = 101;
        for g_deg in 1..100 {
            let f = DensePolynomial::<Fr>::rand(degree, rng);
            let mut g = DensePolynomial::<Fr>::rand(g_deg, rng);
            *g.last_mut().unwrap() = Fr::one(); //monic

            let (q, r) = fast_divide_monic(&f, &g);

            let t = &(&q * &g) + &r;

            for (i, j) in t.coeffs.iter().zip(f.coeffs.iter()) {
                assert_eq!(*i, *j);
            }
        }
    }

    #[test]
    fn test_interpolate() {
        let rng = &mut ark_std::test_rng();
        for d in 1..100 {
            let mut points = vec![];
            let mut evals = vec![];
            for _ in 0..d {
                points.push(Fr::rand(rng));
                evals.push(Fr::rand(rng));
            }

            let s = subproduct_tree(&points);
            let p = fast_interpolate(&points, &evals, &s);

            for (x, y) in points.iter().zip(evals.iter()) {
                assert_eq!(p.evaluate(x), *y)
            }
        }
    }

    #[test]
    fn test_linear_combine() {
        let rng = &mut ark_std::test_rng();
        for d in 1..100 {
            let mut u = vec![];
            let mut c = vec![];
            for _ in 0..d {
                u.push(Fr::rand(rng));
                c.push(Fr::rand(rng));
            }
            let s = subproduct_tree(&u);
            let f = fast_linear_combine(&u, &c, &s);

            let r = Fr::rand(rng);
            let m = s.M.evaluate(&r);
            let mut total = Fr::zero();
            for (u_i, c_i) in u.iter().zip(c.iter()) {
                total += m * *c_i / (r - u_i);
            }
            assert_eq!(f.evaluate(&r), total);
        }
    }

    #[test]
    fn test_inv_lagrange() {
        let rng = &mut ark_std::test_rng();
        for d in 1..100 {
            let mut u = vec![];
            for _ in 0..d {
                u.push(Fr::rand(rng));
            }
            let s = subproduct_tree(&u);
            let f = fast_inverse_lagrange_coefficients(&u, &s);

            let s_prime = derivative(&s.M);

            for (a, (i, j)) in u.iter().zip(f.iter()).enumerate() {
                dbg!(a);
                assert_eq!(s_prime.evaluate(i), *j);
            }
        }
    }
}
