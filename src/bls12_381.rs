/*
Operations involving BLS12-381.
*/

use bls12_381::{G1Affine, G1Projective};

/*
Polynomials are represented as vectors of G1 points.
The first element of the vector is the free coefficient of the polynomial.
For example, the polynomial
`f(x) = c_0 + c_1 * x + ... + c_{t-1} * x^{t-1}`
is encoded as
`vec![c_0,  c_1, ..., c_{t-1}]`.
*/
pub struct Poly(Vec<G1Affine>);

// Addition in affine coordinates
fn add_affine(x: G1Affine, y: G1Affine) -> G1Affine {
    G1Affine::from(G1Projective::from(x) + G1Projective::from(y))
}

/*
Clear trailing zero coefficients in a polynomial.
For example,
`clear_trailing_zeros(!vec[a, b, 0, c, 0]) == !vec[a, b, 0, c]`.
*/
fn clear_trailing_zeros(poly: Poly) -> Poly {
    let mut res = poly
        .0
        .into_iter()
        .rev()
        .skip_while(|g1| bool::from(G1Affine::is_identity(g1)))
        .collect::<Vec<_>>();
    res.reverse();
    Poly(res)
}

/*
Addition on polynomials is defined such that the `i`th coefficients are added.
ie. `f(x) + g(x) = (f_0 + g_0) + (f_1 + g_1) * x + ...`
*/
impl std::ops::Add for Poly {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        // right-pad with zeros such that both polynomials are of the same degree
        let mut f = self.0;
        let mut g = other.0;
        let degree = std::cmp::max(f.len(), g.len());
        f.resize(degree, G1Affine::identity());
        g.resize(degree, G1Affine::identity());

        // zip f and g with addition in G1
        let zipper = f.iter().zip(g.iter());
        let res = zipper.map(|(x, y)| add_affine(*x, *y)).collect();
        clear_trailing_zeros(Self(res))
    }
}
