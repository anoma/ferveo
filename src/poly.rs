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
    let mut res = true;
    // ∀ l ∈ [0, t]. 1_{G1} * s_l = ∑_{j=0}^t (p_j_l * i * j)
    for (l, s_l) in s.iter().enumerate() {
        let lhs = G1Affine::generator() * s_l;
        let mut rhs = G1Projective::identity();
        let mut j = Scalar::zero();
        for p_j in p.iter() {
            rhs += p_j[l] * i * j;
            j += Scalar::one()
        }
        res &= lhs == rhs
    }
    res
}
