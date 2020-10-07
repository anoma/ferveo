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
