/*
Operations involving polynomials.
*/

use bls12_381::{G1Affine, G1Projective, Scalar};
use ff;
use rand;

/*
A Public polynomial, used during the setup phase.
The element at (0, 0) is the free coefficient of the polynomial.
For example, the polynomial
`f(x, y) = c_0_0 + ... + c_i_j * x^i * j^i + ... + c_{t-1}_{t-1} * x^{t-1} * y^{t-1}`
is encoded as
`vec![vec![c_0_0, ..., c_0_{t-1}], ..., vec![c_{t-1}_0, ..., c_{t-1}_{t-1}]]`.
*/
type Public = Vec<Vec<G1Affine>>;

/*
A secret polynomial, used during the setup phase.
The element at (0, 0) is the free coefficient of the polynomial.
For example, the polynomial
`f(x, y) = c_0_0 + ... + c_i_j * x^i * j^i + ... + c_{t-1}_{t-1} * x^{t-1} * y^{t-1}`
is encoded as
`vec![vec![c_0_0, ..., c_0_{t-1}], ..., vec![c_{t-1}_0, ..., c_{t-1}_{t-1}]]`.
*/
type Secret = Vec<Vec<Scalar>>;

/*
A secret share, used during the setup phase.
The element at 0 is the free coefficient of the polynomial.
For example, the polynomial
`f(y) = c_0 + ... + c_i * y^i + ... + c_{t-1} * y^{t-1}`
is encoded as
`vec![c_0, ..., c_{t-1}]`.
*/
type Share = Vec<Scalar>;

// Addition in affine coordinates
fn add_g1_affine(x: G1Affine, y: G1Affine) -> G1Affine {
    G1Affine::from(G1Projective::from(x) + G1Projective::from(y))
}

/*
Addition on polynomials is defined such that the `(i, j)`th coefficients are added.
ie. `f(x) + g(x) = (f_i_j + g_i_j) * x^i * y^j`
*/
fn add_public(f: Public, g: Public) -> Public {
    // zip f and g with addition in G1
    f.iter()
        .zip(g.iter())
        .map(|(f_j, g_j)| {
            f_j.iter()
                .zip(g_j.iter())
                .map(|(f_i_j, g_i_j)| add_g1_affine(*f_i_j, *g_i_j))
                .collect()
        })
        .collect()
}

/*
Addition on polynomials is defined such that the `(i, j)`th coefficients are added.
ie. `f(x) + g(x) = (f_i_j + g_i_j) * x^i * y^j`
*/
fn add_secret(f: Secret, g: Secret) -> Secret {
    // zip f and g with addition in Fr
    f.iter()
        .zip(g.iter())
        .map(|(f_j, g_j)| {
            f_j.iter()
                .zip(g_j.iter())
                .map(|(f_i_j, g_i_j)| *f_i_j + *g_i_j)
                .collect()
        })
        .collect()
}

// Evaluate a public polynomial at a particular point.
fn eval_public(f: Public, (x, y): (Scalar, Scalar)) -> G1Affine {
    let mut xi = Scalar::one(); // x^i
    let mut res = G1Projective::identity();
    for f_i in f.iter() {
        let mut yj = Scalar::one(); // y^j
        for f_i_j in f_i.iter() {
            res += f_i_j * xi * yj;
            yj *= y;
        }
        xi *= x;
    }
    G1Affine::from(res)
}

/*
Partially evaluate a secret polynomial at a particular point `x`.
`eval_secret_x(f, x) ≅ f(x)` where `≅` is isomorphism.
*/
fn eval_secret_x(f: Secret, x: Scalar) -> Share {
    let mut xi = Scalar::one(); // x^i
    let mut res = vec![Scalar::zero(); f.len()];
    for f_i in f.iter() {
        for (j, f_i_j) in f_i.iter().enumerate() {
            res[j] += f_i_j * xi;
        }
        xi *= x;
    }
    res
}

// Evaluate a share at a particular point.
fn eval_share(f: Share, x: Scalar) -> Scalar {
    let mut xi = Scalar::one(); // x^i
    let mut res = Scalar::zero();
    for f_i in f.iter() {
        res += f_i * xi;
        xi *= x
    }
    res
}

// Evaluate a secret polynomial at a particular point.
fn eval_secret(f: Secret, (x, y): (Scalar, Scalar)) -> Scalar {
    let mut xi = Scalar::one(); // x^i
    let mut res = Scalar::zero();
    for f_i in f.iter() {
        let mut yj = Scalar::one(); // y^j
        for f_i_j in f_i.iter() {
            res += f_i_j * xi * yj;
            yj *= y;
        }
        xi *= x;
    }
    res
}

// Generate a random secret polynomial of order `threshold`.
fn random_secret<R: rand::Rng + Sized>(threshold: i32, mut rng: R) -> Secret {
    let mut res = Vec::new();
    for _ in 0..threshold {
        let mut res_i = Vec::new();
        for _ in 0..threshold {
            res_i.push(<Scalar as ff::Field>::random(&mut rng))
        }
        res.push(res_i);
    }
    res
}

// Generate the public polynomial for a given secret polynomial.
fn public(f: Secret) -> Public {
    f.iter()
        .map(|f_i| {
            f_i.iter()
                .map(|v| G1Affine::generator() * v)
                .map(|v| G1Affine::from(v))
                .collect()
        })
        .collect()
}

// Generate the `j`th secret share
fn share(f: Secret, j: u32) -> Share {
    let j = Scalar::from(u64::from(j));
    eval_secret_x(f, j)
}

// Verify that the given share with index `i` is consistent with the public polynomial.
fn verify_share(p: Public, s: Share, i: u32) -> bool {
    let i = Scalar::from(u64::from(i));

    // ∀ l ∈ [0, t]. 1_{G1} * s_l = ∑_{j=0}^t (p_j_l * i * j)
    let mut res = true;
    for (l, s_l) in s.iter().enumerate() {
        let lhs = G1Affine::generator() * s_l;
        let mut rhs = G1Projective::identity();
        for (j, p_j) in p.iter().enumerate() {
            rhs += p_j[l] * i * Scalar::from(j as u64)
        }
        res &= lhs == rhs
    }
    res
}

// Verify that a given point from node `m` with index `i` is consistent with the public polynomial.
fn verify_point(p: Public, i: u32, m: u32, x: Scalar) -> bool {
    let i = Scalar::from(u64::from(i));
    let m = Scalar::from(u64::from(m));

    // Scalar exponentiation by u64. `exp(x, y) = x^y`
    fn exp(x: Scalar, y: u64) -> Scalar {
        let y = [u64::to_le(y), 0, 0, 0];
        x.pow(&y)
    }

    // 1_{G1} * x = ∑_{j,l=0}^t (p_j_l * m^j * i^l)
    let lhs = G1Affine::generator() * x;
    let mut rhs = G1Projective::identity();
    for (j, p_j) in p.iter().enumerate() {
        for (l, p_j_l) in p_j.iter().enumerate() {
            rhs += p_j_l * exp(m, j as u64) * exp(i, l as u64)
        }
    }
    lhs == rhs
}
