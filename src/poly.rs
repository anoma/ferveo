/*
Operations involving polynomials.
*/

use crate::bls12_381::{G1Affine, G1Projective, Scalar};
use ff;
use nalgebra::base::{DMatrix, DVector};
use rand;

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

/*
Addition on polynomials is defined such that the `(i, j)`th coefficients are added.
ie. `f(x) + g(x) = (f_i_j + g_i_j) * x^i * y^j`
*/
fn add_public(f: Public, g: Public) -> Public {
    f + g
}

/*
Addition on polynomials is defined such that the `(i, j)`th coefficients are added.
ie. `f(x) + g(x) = (f_i_j + g_i_j) * x^i * y^j`
*/
fn add_secret(f: Secret, g: Secret) -> Secret {
    f + g
}

// Powers of `x` from 0 to `n`.
fn powers(x: Scalar, n: usize) -> Vec<Scalar> {
    let mut res = Vec::new();
    let mut xi = Scalar::zero(); // x^i
    for _ in 0..n {
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
        .sum()
        .into()
}

/*
Partially evaluate a secret polynomial at a particular point `x`.
`eval_secret_x(f, x) ≅ f(x)` where `≅` is isomorphism.
*/
fn eval_secret_x(f: Secret, x: Scalar) -> Share {
    let xi = powers(x, f.ncols() - 1); // x^i from 0 to ncols - 1
    f.map_with_location(|j, i, fij| fij * xi[i]).column_sum()
}

// Evaluate a share at a particular point.
fn eval_share(f: Share, x: Scalar) -> Scalar {
    let xi = powers(x, f.ncols() - 1); // x^i from 0 to ncols - 1
    f.iter().enumerate().map(|(i, fi)| *fi * xi[i]).sum()
}

// Evaluate a secret polynomial at a particular point.
fn eval_secret(f: Secret, (x, y): (Scalar, Scalar)) -> Scalar {
    let xi = powers(x, f.ncols() - 1); // x^i from 0 to ncols - 1
    let yj = powers(y, f.nrows() - 1); // y^j from 0 to nrows - 1
    f.map_with_location(|j, i, fij| fij * xi[i] * yj[j]).sum()
}

// Generate a random secret polynomial of order `threshold`.
fn random_secret<R: rand::Rng + Sized>(threshold: i32, mut rng: R) -> Secret {
    let threshold = threshold as usize;
    DMatrix::from_fn(threshold, threshold, |_, _| Scalar::random(&mut rng))
}

// Generate the public polynomial for a given secret polynomial.
fn public(f: Secret) -> Public {
    f.map(|fij| (G1Projective::one() * fij).into())
}

// Generate the `j`th secret share
fn share(f: Secret, j: u32) -> Share {
    eval_secret_x(f, j.into())
}

// Verify that the given share with index `i` is consistent with the public polynomial.
fn verify_share(p: Public, s: Share, i: u32) -> bool {
    // ∀ l ∈ [0, t]. 1_{G1} * s_l = ∑_{j=0}^t (p_j_l * i * j)
    s.iter().enumerate().all(|(l, sl)| {
        let lhs = G1Projective::one() * *sl;
        let rhs = p
            .column_iter()
            .enumerate()
            .map(|(j, pj)| pj[l] * i.into() * (j as u64).into())
            .sum();
        lhs == rhs
    })
}

// Verify that a given point from node `m` with index `i` is consistent with the public polynomial.
fn verify_point(p: Public, i: u32, m: u32, x: Scalar) -> bool {
    // Scalar exponentiation by u64. `exp(x, y) = x^y`
    fn exp<X: Into<Scalar>>(x: X, y: u64) -> Scalar {
        let y = [u64::to_le(y), 0, 0, 0];
        x.into().pow(&y)
    }

    // 1_{G1} * x = ∑_{j,l=0}^t (p_j_l * m^j * i^l)
    let lhs = G1Projective::one() * x;
    let rhs = p
        .map_with_location(|l, j, pjl| pjl * exp(m, j as u64) * exp(i, l as u64))
        .sum();
    lhs == rhs
}

// Polynomial product
fn poly_prod(x: DVector<Scalar>, y: DVector<Scalar>) -> DVector<Scalar> {
    let mut res = DVector::from_element(x.len() + y.len() - 1, Scalar::zero());
    for (i, xi) in x.iter().enumerate() {
        for (j, yj) in y.iter().enumerate() {
            res[(0, i + j)] += *xi * *yj
        }
    }
    res
}
