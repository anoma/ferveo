/*
Operations involving polynomials.
*/

use bls12_381::{G1Affine, G1Projective, Scalar};
use nalgebra::base::{DMatrix, DVector};

/*
A Public polynomial, used during the setup phase.
The element at (0, 0) is the free coefficient of the polynomial.
For example, the polynomial
`f(x, y) = c_0_0 + ... + c_i_j * x^i * j^i + ... + c_{t-1}_{t-1} * x^{t-1} * y^{t-1}`
is encoded as
`vec![vec![c_0_0, ..., c_0_{t-1}], ..., vec![c_{t-1}_0, ..., c_{t-1}_{t-1}]]`.
*/
type Public = DMatrix<G1Affine>;

/*
A secret polynomial, used during the setup phase.
The element at (0, 0) is the free coefficient of the polynomial.
For example, the polynomial
`f(x, y) = c_0_0 + ... + c_i_j * x^i * j^i + ... + c_{t-1}_{t-1} * x^{t-1} * y^{t-1}`
is encoded as
`vec![vec![c_0_0, ..., c_0_{t-1}], ..., vec![c_{t-1}_0, ..., c_{t-1}_{t-1}]]`.
*/

type Secret = DMatrix<Scalar>;

/*
A secret share, used during the setup phase.
The element at 0 is the free coefficient of the polynomial.
For example, the polynomial
`f(y) = c_0 + ... + c_i * y^i + ... + c_{t-1} * y^{t-1}`
is encoded as
`vec![c_0, ..., c_{t-1}]`.
*/
type Share = DVector<Scalar>;

// Powers of `x` from 0 to `n`.
fn powers(x: Scalar, n: usize) -> Vec<Scalar> {
    let mut res = Vec::new();
    let mut xi = Scalar::one(); // x^i
    for _ in 0..=n {
        res.push(xi);
        xi *= x
    }
    res
}

// Evaluate a public polynomial at a particular point.
fn eval_public(f: Public, (x, y): (Scalar, Scalar)) -> G1Affine {
    let xi = powers(x, f.ncols() - 1); // x^i from 0 to ncols - 1
    let yj = powers(y, f.nrows() - 1); // y^j from 0 to nrows - 1
    f.map_with_location(|j, i, fij| fij * xi[i] * yj[j])
        .iter()
        .sum::<G1Projective>()
        .into()
}

/*
Partially evaluate a secret polynomial at a particular point `x`.
`eval_secret_x(f, x) ≅ f(x)` where `≅` is isomorphism.
*/
fn eval_secret_x(f: &Secret, x: Scalar) -> Share {
    let xi = powers(x, f.ncols() - 1); // x^i from 0 to ncols - 1
    let mut res = DVector::from_element(f.nrows(), Scalar::zero());
    for (j, fj) in f.row_iter().enumerate() {
        for (i, fij) in fj.iter().enumerate() {
            res[j] += fij * xi[i]
        }
    }
    res
}

// Evaluate a share at a particular point.
fn eval_share(f: &Share, x: Scalar) -> Scalar {
    let xi = powers(x, f.len() - 1); // x^i from 0 to ncols - 1
    let mut res = Scalar::zero();
    for (i, fi) in f.iter().enumerate() {
        res += fi * xi[i]
    }
    res
}

// Evaluate a secret polynomial at a particular point.
fn eval_secret(f: Secret, (x, y): (Scalar, Scalar)) -> Scalar {
    let xi = powers(x, f.ncols() - 1); // x^i from 0 to ncols - 1
    let yj = powers(y, f.nrows() - 1); // y^j from 0 to nrows - 1
    let mut res = Scalar::zero();
    for (i, fi) in f.column_iter().enumerate() {
        for (j, fij) in fi.iter().enumerate() {
            res += fij * xi[i] * yj[j]
        }
    }
    res
}

// Generate a random secret polynomial of order `threshold`.
fn random_secret<R: rand::Rng + Sized>(threshold: u32, mut rng: R) -> Secret {
    let threshold = threshold as usize;
    let mut res =
        unsafe { DMatrix::new_uninitialized(threshold + 1, threshold + 1) };
    // secret polynomials are bivariate, so res[i][j] = res[j][i]
    for i in 0..=threshold {
        for j in 0..=i {
            res[(j, i)] = <Scalar as ff::Field>::random(&mut rng);
            if i != j {
                res[(i, j)] = res[(j, i)]
            }
        }
    }
    res
}

// Generate the public polynomial for a given secret polynomial.
fn public(f: &Secret) -> Public {
    f.map(|fij| (G1Projective::generator() * fij).into())
}

// Generate the `j`th secret share
fn share(f: &Secret, j: u32) -> Share {
    eval_secret_x(f, (j as u64).into())
}

// Scalar exponentiation by u64. `exp(x, y) = x^y`
fn scalar_exp_u64(x: Scalar, y: u64) -> Scalar {
    x.pow(&[u64::to_le(y), 0, 0, 0])
}

// Verify that the given share with index `i` is consistent with the public polynomial.
fn verify_share(p: &Public, s: Share, i: u32) -> bool {
    // ∀ l ∈ [0, t]. 1_{G1} * s_l = ∑_{j=0}^t (p_j_l * i^j)
    s.iter().enumerate().all(|(l, sl)| {
        let lhs = G1Projective::generator() * *sl;
        let mut rhs = G1Projective::identity();
        for (j, pj) in p.column_iter().enumerate() {
            rhs += pj[l] * scalar_exp_u64((i as u64).into(), j as u64)
        }
        lhs == rhs
    })
}

// Verify that a given point from node `m` with index `i` is consistent with the public polynomial.
fn verify_point(p: &Public, i: u32, m: u32, x: Scalar) -> bool {
    let i = Scalar::from(i as u64);
    let m = Scalar::from(m as u64);

    // 1_{G1} * x = ∑_{j,l=0}^t (p_j_l * m^j * i^l)
    let lhs = G1Projective::generator() * x;
    let rhs = p
        .map_with_location(|l, j, pjl| {
            pjl * scalar_exp_u64(m, j as u64) * scalar_exp_u64(i, l as u64)
        })
        .iter()
        .sum();
    lhs == rhs
}

// Polynomial sum
fn poly_sum(x: DVector<Scalar>, y: DVector<Scalar>) -> DVector<Scalar> {
    let res_size = std::cmp::max(x.len(), y.len());
    let x = x.resize_vertically(res_size, Scalar::zero());
    let y = y.resize_vertically(res_size, Scalar::zero());
    x + y
}

// Polynomial product
fn poly_prod(x: DVector<Scalar>, y: DVector<Scalar>) -> DVector<Scalar> {
    let mut res = DVector::from_element(x.len() + y.len() - 1, Scalar::zero());
    for (i, xi) in x.iter().enumerate() {
        for (j, yj) in y.iter().enumerate() {
            res[(i + j, 0)] += *xi * *yj
        }
    }
    res
}

// lagrange basis polynomial L_n_j(x)
fn lagrange_basis(j: usize, xs: &DVector<Scalar>) -> DVector<Scalar> {
    let mut num = DVector::from_element(1, Scalar::one()); // numerator
    let mut den = Scalar::one(); // denominator
    for (k, xk) in xs.iter().enumerate() {
        if k != j {
            num =
                poly_prod(num, DVector::from_vec(vec![-(*xk), Scalar::one()]));
            den *= xs[j] - *xk
        }
    }
    den = den.invert().unwrap();
    num.map(|v| v * den)
}

pub fn lagrange_interpolate(
    points: DVector<(Scalar, Scalar)>,
) -> DVector<Scalar> {
    let xs = points.map(|(x, _)| x);
    let ys = points.map(|(_, y)| y);
    let mut res = DVector::from_vec(Vec::new());
    for (j, yj) in ys.iter().enumerate() {
        res = poly_sum(res, lagrange_basis(j, &xs).map(|v| v * *yj))
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_secret_is_symmetric() {
        let threshold = 40;
        let secret = random_secret(threshold, rand::thread_rng());
        for i in 0..(threshold as usize) {
            for j in 0..i {
                assert!(secret[(i, j)] == secret[(j, i)])
            }
        }
    }

    #[test]
    fn share_verification() {
        let threshold = 10;
        let secret = random_secret(threshold, rand::thread_rng());
        let public = public(&secret);
        for i in 0..(threshold * 2) {
            assert!(verify_share(&public, share(&secret, i), i))
        }
    }

    #[test]
    fn point_verification() {
        let threshold = 7;
        let secret = random_secret(threshold, rand::thread_rng());
        let public = public(&secret);
        for i in 0..threshold {
            let share = share(&secret, i);
            for j in 0..threshold {
                let point = eval_share(&share, (j as u64).into());
                assert!(verify_point(&public, j, i, point))
            }
        }
    }
}
