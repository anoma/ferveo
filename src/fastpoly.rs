use ark_bls12_381::Fr;
use ark_bls12_381::G1Projective;
use ark_ff::{One, Zero};
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly::UVPolynomial;

/*pub fn reduce_xl(f: &DensePolynomial<Fr>, l: usize) -> DensePolynomial<Fr> {
    let mut res = DensePolynomial::<Fr> {
        coeffs: vec![Fr::zero(); l],
    };
    for chunk in f.coeffs.chunks(l) {
        for (r, p) in res.iter_mut().zip(chunk.iter()) {
            *r += p;
        }
    }
    res
}*/

pub fn inverse_mod_xl(
    f: &DensePolynomial<Fr>,
    l: usize,
) -> Option<DensePolynomial<Fr>> {
    use ark_ff::Field;
    use std::ops::Mul;
    //let r =
    //    std::mem::size_of::<u64>() * 8 - (l as u64).leading_zeros() as usize; // ceil(log_2(l))

    //assert_eq!((l as f64).log2().ceil() as usize, r);
    let r = (l as f64).log2().ceil() as usize;
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

/*pub fn subproduct_tree(u: &[Fr]) -> SubproductTree {
    let mut subproduct_tree = std::collections::VecDeque::new();
    for u_i in u.iter() {
        let m_i = DensePolynomial::<Fr> {
            coeffs: vec![-*u_i, Fr::one()],
        };
        subproduct_tree.push_back(SubproductTree {
            left: None,
            right: None,
            M: m_i,
        });
    }

    loop {
        if subproduct_tree.len() == 1 {
            return subproduct_tree.pop_front().unwrap();
        }
        let left = Box::new(subproduct_tree.pop_front().unwrap());
        let right = Box::new(subproduct_tree.pop_front().unwrap());
        let tree = SubproductTree {
            left,
            right,
            M: &left.M * &right.M,
        };
        subproduct_tree.push_back(tree);
    }
}*/

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

/*pub fn split_slice<'a>(x: &'a [Fr]) -> (&'a [Fr], &'a [Fr]) {
    let n = x.len() / 2;
    (&x[..n], &x[n..])
}

pub fn split_slice_mut<'a>(x: &'a mut [Fr]) -> (&'a mut [Fr], &'a mut [Fr]) {
    let n = x.len() / 2;
    (&mut x[..n], &mut x[n..])
}*/

pub fn fast_evaluate(
    f: &DensePolynomial<Fr>,
    u: &[Fr],
    s: &SubproductTree,
    t: &mut [Fr],
) {
    if u.len() == 1 {
        t[0] = f.coeffs[0];
        return;
    }

    let left = s.left.as_ref().unwrap();
    let right = s.right.as_ref().unwrap();
    let (_, r_0) = fast_divide_monic(f, &left.M);
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
    if u.len() == 1 {
        return DensePolynomial::<Fr> { coeffs: vec![v[0]] };
    }
    let n = u.len() / 2;
    let (u_0, u_1) = u.split_at(n);
    let (v_0, v_1) = v.split_at(n);

    let left = s.left.as_ref().unwrap();
    let right = s.right.as_ref().unwrap();

    let mut evals = vec![Fr::zero(); u.len()];
    let (evals_0, evals_1) = evals.split_at_mut(n);

    let m_prime = derivative(&s.M);
    fast_evaluate(&m_prime, u_0, &left, evals_0);
    fast_evaluate(&m_prime, u_1, &right, evals_1);

    for (s_i, v_i) in evals.iter_mut().zip(v.iter()) {
        *s_i = s_i.inverse().unwrap() * *v_i;
    }

    fast_linear_combine(u, &evals, &s)
}

pub fn fast_interpolate_and_batch(
    u: &[Fr],
    v: &[Fr],
    points: &[G1Projective],
    s: &SubproductTree,
    normalize: Option<Fr>,
) -> (DensePolynomial<Fr>, G1Projective) {
    use ark_ff::Field;
    if u.len() == 1 {
        return (DensePolynomial::<Fr> { coeffs: vec![v[0]] }, points[0]); //TODO: is this correct?
    }
    let n = u.len() / 2;
    let (u_0, u_1) = u.split_at(n);
    let (v_0, v_1) = v.split_at(n);

    let left = s.left.as_ref().unwrap();
    let right = s.right.as_ref().unwrap();

    let mut evals = vec![Fr::zero(); u.len()];
    let (evals_0, evals_1) = evals.split_at_mut(n);

    let m_prime = derivative(&s.M);
    fast_evaluate(&m_prime, u_0, &left, evals_0);
    fast_evaluate(&m_prime, u_1, &right, evals_1);

    let mut c = evals
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

#[test]
fn test_inverse() {
    use ark_poly::Polynomial;
    use ark_std::test_rng;
    let rng = &mut test_rng();

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
    use ark_poly::Polynomial;
    use ark_std::test_rng;
    let rng = &mut test_rng();

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
    use ark_poly::Polynomial;
    use ark_std::UniformRand;
    let rng = &mut ark_std::test_rng();
    let mut points = vec![];
    let mut evals = vec![];
    for _ in 0..100 {
        points.push(Fr::rand(rng));
        evals.push(Fr::rand(rng));
    }

    let s = subproduct_tree(&points);
    let p = fast_interpolate(&points, &evals, &s);

    for (x, y) in points.iter().zip(evals.iter()) {
        assert_eq!(p.evaluate(x), *y)
    }
}
