/*
Operations involving polynomials.
*/

use bls12_381::{G1Affine, G1Projective, Scalar};
use ff;
use rand;

/*
A Public polynomial, used during the setup phase.
The first element of the vector is the free coefficient of the polynomial.
For example, the polynomial
`f(x) = c_0 + c_1 * x + ... + c_{t-1} * x^{t-1}`
is encoded as
`vec![c_0,  c_1, ..., c_{t-1}]`.
*/
type Public = Vec<G1Affine>;

/*
A secret polynomial, used during the setup phase.
The first element of the vector is the free coefficient of the polynomial.
For example, the polynomial
`f(x) = c_0 + c_1 * x + ... + c_{t-1} * x^{t-1}`
is encoded as
`vec![c_0,  c_1, ..., c_{t-1}]`.
*/
type Secret = Vec<Scalar>;

// Addition in affine coordinates
fn add_g1_affine(x: G1Affine, y: G1Affine) -> G1Affine {
    G1Affine::from(G1Projective::from(x) + G1Projective::from(y))
}

/*
Addition on polynomials is defined such that the `i`th coefficients are added.
ie. `f(x) + g(x) = (f_0 + g_0) + (f_1 + g_1) * x + ...`
*/
fn add_public(f: Public, g: Public) -> Public {
    // right-pad with zeros such that both polynomials are of the same degree
    let mut f = f;
    let mut g = g;
    let degree = std::cmp::max(f.len(), g.len());
    f.resize(degree, G1Affine::identity());
    g.resize(degree, G1Affine::identity());

    // zip f and g with addition in G1
    let zipper = f.iter().zip(g.iter());
    zipper.map(|(x, y)| add_g1_affine(*x, *y)).collect()
}

/*
Addition on polynomials is defined such that the `i`th coefficients are added.
ie. `f(x) + g(x) = (f_0 + g_0) + (f_1 + g_1) * x + ...`
*/
fn add_secret(f: Secret, g: Secret) -> Secret {
    // right-pad with zeros such that both polynomials are of the same degree
    let mut f = f;
    let mut g = g;
    let degree = std::cmp::max(f.len(), g.len());
    f.resize(degree, Scalar::zero());
    g.resize(degree, Scalar::zero());

    // zip f and g with addition in G1
    let zipper = f.iter().zip(g.iter());
    zipper.map(|(x, y)| *x + *y).collect()
}

// Evaluate a public polynomial at a particular point.
fn eval_public(public: Public, point: Scalar) -> G1Affine {
    let mut v = Scalar::one();
    let mut res = G1Projective::identity();
    for coefficient in public.iter() {
        res += coefficient * v;
        v *= point;
    }
    G1Affine::from(res)
}

// Evaluate a secret polynomial at a particular point.
fn eval_secret(secret: Secret, point: Scalar) -> Scalar {
    let mut v = Scalar::one();
    let mut res = Scalar::zero();
    for coefficient in secret.iter() {
        res += coefficient * v;
        v *= point;
    }
    res
}

// Generate a random secret polynomial of length `threshold`.
fn random_secret<R: rand::Rng + Sized>(threshold: i32, mut rng: R) -> Secret {
    let mut res = Vec::new();
    for _ in 0..threshold {
        res.push(<Scalar as ff::Field>::random(&mut rng))
    }
    res
}

// Generate the public polynomial for a given secret polynomial.
fn public(secret: Secret) -> Public {
    secret
        .iter()
        .map(|v| G1Affine::generator() * v)
        .map(|v| G1Affine::from(v))
        .collect()
}
