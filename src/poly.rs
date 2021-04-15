/*
Operations involving polynomials.
*/

use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::wnaf::WnafContext;
use ark_ec::ProjectiveCurve;
use ark_ff::{Field, UniformRand};
use ark_poly::polynomial::multivariate::{SparsePolynomial, SparseTerm, Term};
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly::polynomial::{MVPolynomial, Polynomial, UVPolynomial};
use num::{One, Zero};

use crate::fft;

pub type Scalar = Fr;

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

// Scalar exponentiation by u64. `exp(x, y) = x^y`
fn scalar_exp_u64(x: Scalar, y: u64) -> Scalar {
    x.pow([u64::to_le(y)])
}

// Scalar exponentiation by usize. `exp(x, y) = x^y`
fn scalar_exp_usize(x: Scalar, y: usize) -> Scalar {
    scalar_exp_u64(x, y as u64)
}

// Univariate polynomial
pub type Univar = DensePolynomial<Scalar>;

// the exponent of the nth parameter in a term
fn param_pow(term: &SparseTerm, i: usize) -> usize {
    *term
        .iter()
        .find_map(|(par, deg)| if *par == i { Some(deg) } else { None })
        .unwrap_or(&0)
}

// Bivariate polynomial
pub struct Bivar(SparsePolynomial<Scalar, SparseTerm>);

impl Bivar {
    // get the degree of the first term
    fn fst_degree(&self) -> usize {
        self.0
            .terms
            .iter()
            .map(|(_, term)| param_pow(term, 0))
            .max()
            .unwrap()
    }

    // get the degree of the second term
    fn snd_degree(&self) -> usize {
        self.0
            .terms
            .iter()
            .map(|(_, term)| param_pow(term, 1))
            .max()
            .unwrap()
    }

    pub fn coeffs(&self) -> Vec<Vec<Scalar>> {
        let fst_degree = self.fst_degree();
        let snd_degree = self.snd_degree();

        let mut res =
            vec![vec![Scalar::zero(); snd_degree + 1]; fst_degree + 1];

        self.0.terms.iter().for_each(|(coeff, term)| {
            let pow_fst = param_pow(term, 0);
            let pow_snd = param_pow(term, 1);
            res[pow_fst][pow_snd] += coeff;
        });

        res
    }

    pub fn from_coeffs(coeffs: &Vec<Vec<Scalar>>) -> Self {
        let mut coeffs_vec = Vec::new();

        for i in 0..coeffs.len() {
            for j in 0..coeffs[0].len() {
                let term = SparseTerm::new(vec![(0, i), (1, j)]);
                let coeff = (coeffs[i][j], term);
                coeffs_vec.push(coeff)
            }
        }

        Bivar(SparsePolynomial::from_coefficients_vec(2, coeffs_vec))
    }

    // evaluate at the first term
    pub fn eval_fst(&self, fst: Scalar) -> Univar {
        let coeffs = self.coeffs();
        let pows_fst = powers(fst, self.fst_degree() + 1); // powers of fst

        let mut res = vec![Scalar::zero(); self.snd_degree() + 1];

        coeffs.into_iter().enumerate().for_each(|(i, coeffs_snds)| {
            coeffs_snds
                .into_iter()
                .enumerate()
                .for_each(|(j, coeff)| res[j] += coeff * pows_fst[i]);
        });

        Univar::from_coefficients_vec(res)
    }

    // Generate a random symmetric bivariate polynomial of order `threshold`.
    pub fn random_symmetric_secret<R: rand::Rng + Sized>(
        threshold: u32,
        rng: &mut R,
    ) -> Secret {
        let threshold = threshold as usize;
        let mut coeffs =
            vec![vec![Scalar::zero(); threshold + 1]; threshold + 1];

        // by symmetry, `res[i][j] = res[j][i]`
        for i in 0..=threshold {
            for j in 0..=i {
                let coeff = Scalar::rand(rng);
                coeffs[i][j] += coeff;
                if i != j {
                    coeffs[j][i] += coeff
                }
            }
        }

        Bivar::from_coeffs(&coeffs)
    }
}

/*
A Public polynomial, used during the setup phase.
The element at (0, 0) is the free coefficient of the polynomial.
For example, the polynomial
`f(x, y) = c_0_0 + ... + c_i_j * x^i * j^i + ... + c_{t-1}_{t-1} * x^{t-1} * y^{t-1}`
is encoded as
`vec![vec![c_0_0, ..., c_0_{t-1}], ..., vec![c_{t-1}_0, ..., c_{t-1}_{t-1}]]`.
*/
pub type Public = Vec<Vec<G1Affine>>;

// add two public polynomial commitments
pub fn add_public(lhs: &Public, rhs: &Public) -> Public {
    lhs.iter()
        .enumerate()
        .map(|(i, lhs_i)| {
            lhs_i
                .iter()
                .enumerate()
                .map(|(j, lhs_ij)| *lhs_ij + rhs[i][j])
                .collect()
        })
        .collect()
}

/*
A secret polynomial, used during the setup phase.
The element at (0, 0) is the free coefficient of the polynomial.
For example, the polynomial
`f(x, y) = c_0_0 + ... + c_i_j * x^i * j^i + ... + c_{t-1}_{t-1} * x^{t-1} * y^{t-1}`
is encoded as
`vec![vec![c_0_0, ..., c_0_{t-1}], ..., vec![c_{t-1}_0, ..., c_{t-1}_{t-1}]]`.
*/
pub type Secret = Bivar;

/*
A secret share, used during the setup phase.
The element at 0 is the free coefficient of the polynomial.
For example, the polynomial
`f(y) = c_0 + ... + c_i * y^i + ... + c_{t-1} * y^{t-1}`
is encoded as
`vec![c_0, ..., c_{t-1}]`.
*/
pub type Share = Univar;

// Generate a random secret polynomial of order `threshold` from secret `s`
pub fn random_secret<R: rand::Rng + Sized>(
    threshold: u32,
    s: Scalar,
    rng: &mut R,
) -> Secret {
    let threshold = threshold as usize;
    let mut coeffs = vec![vec![Scalar::zero(); threshold + 1]; threshold + 1];

    // secret polynomials are symmetric, so res[i][j] = res[j][i]
    for i in 0..=threshold {
        for j in 0..=i {
            let coeff = Scalar::rand(rng);
            coeffs[i][j] += coeff;
            if i != j {
                coeffs[j][i] += coeff
            }
        }
    }

    coeffs[0][0] = s;

    Bivar::from_coeffs(&coeffs)
}

fn mul_g1proj(lhs: G1Projective, rhs: Scalar) -> G1Projective {
    let mut lhs = lhs;
    lhs *= rhs;
    lhs
}

// Generate the public polynomial for a given secret polynomial.
pub fn public(secret: &Secret) -> Public {
    secret
        .coeffs()
        .into_iter()
        .map(|coeffs| {
            coeffs
                .into_iter()
                .map(|coeff| {
                    mul_g1proj(G1Projective::prime_subgroup_generator(), coeff)
                        .into_affine()
                })
                .collect()
        })
        .collect()
}

pub fn public_wnaf(secret: &Secret) -> Public {
    let window_size = 4; // arbitrarily chosen
    let wnaf = WnafContext::new(window_size);
    secret
        .coeffs()
        .iter()
        .map(|coeffs| {
            coeffs
                .iter()
                .map(|coeff| {
                    wnaf.mul(G1Projective::prime_subgroup_generator(), coeff)
                        .into_affine()
                })
                .collect()
        })
        .collect()
}

// Generate the `j`th secret share
pub fn share(secret: &Secret, j: Scalar) -> Share {
    secret.eval_fst(j)
}

/// Generate `participants` many secret shares
pub fn multi_share(secret: &Secret, participants: usize) -> Vec<Share> {
    let domain = fft::domain(participants);
    let (omega, log_n) = (domain.group_gen, domain.log_size_of_group);

    let num_eval_pts =
        usize::max(participants, secret.fst_degree() + 1).next_power_of_two();

    let mut evals = Vec::with_capacity(secret.snd_degree() + 1);
    for col in secret.coeffs().iter() {
        let mut row = Vec::with_capacity(num_eval_pts);
        row.extend(col.iter());
        row.resize(num_eval_pts, Scalar::zero());
        fft::fft(&mut row, omega, log_n);
        evals.push(row);
    }
    let mut shares = Vec::with_capacity(secret.snd_degree() + 1);
    let mut evals_iters: Vec<_> = evals.iter_mut().map(|e| e.iter()).collect();

    for _ in 0..=secret.snd_degree() {
        let mut share = Vec::with_capacity(num_eval_pts);
        for i in &mut evals_iters {
            if let Some(v) = i.next() {
                share.push(*v);
            }
        }
        shares.push(Share::from_coefficients_vec(share));
    }
    shares
}

// Verify that the given share with index `i` is consistent with the public polynomial.
pub fn verify_share(p: &Public, s: &Share, i: Scalar) -> bool {
    // ∀ l ∈ [0, t]. 1_{G1} * s_l = ∑_{j=0}^t (p_j_l * i^j)
    s.coeffs().iter().enumerate().all(|(l, s_l)| {
        let lhs = mul_g1proj(G1Projective::prime_subgroup_generator(), *s_l);
        let mut rhs = G1Projective::zero();
        for (j, pj) in p.iter().enumerate() {
            rhs += mul_g1proj(pj[l].into(), scalar_exp_usize(i, j))
        }
        lhs == rhs
    })
}

// Verify that the given share with x coordinate `x` is consistent with the public polynomial.
fn verify_share_fft(p: &Public, s: &Share, x: Scalar) -> bool {
    // ∀ l ∈ [0, t]. 1_{G1} * s_l = ∑_{j=0}^t (p_j_l * i^j)
    s.iter().enumerate().all(|(l, sl)| {
        let lhs = mul_g1proj(G1Projective::prime_subgroup_generator(), *sl);
        let mut rhs = G1Projective::zero();
        let mut X = Scalar::one();
        for pj in p.iter() {
            rhs += mul_g1proj(pj[l].into(), X);
            X *= x;
        }
        lhs == rhs
    })
}

// Verify that a given point from node `m` with index `i` is consistent with the public polynomial.
pub fn verify_point(p: &Public, i: Scalar, m: Scalar, x: Scalar) -> bool {
    // 1_{G1} * x = ∑_{j,l=0}^t (p_j_l * m^j * i^l)
    let lhs = mul_g1proj(G1Projective::prime_subgroup_generator(), x);
    let rhs: G1Projective = p
        .into_iter()
        .enumerate()
        .map(|(j, p_j)| {
            p_j.into_iter()
                .enumerate()
                .map(|(l, p_jl)| {
                    mul_g1proj(
                        p_jl.clone().into(),
                        scalar_exp_usize(m, j) * scalar_exp_usize(i, l),
                    )
                })
                .sum::<G1Projective>()
        })
        .sum();
    lhs == rhs
}

// Univariate polynomial product
fn poly_prod(x: &Univar, y: &Univar) -> Univar {
    let mut coeffs = vec![Scalar::zero(); x.degree() + y.degree() + 1];
    for (i, xi) in x.coeffs().iter().enumerate() {
        for (j, yj) in y.coeffs().iter().enumerate() {
            coeffs[i + j] += *xi * *yj
        }
    }
    Univar::from_coefficients_vec(coeffs)
}

// lagrange basis polynomial L_n_j(x)
fn lagrange_basis(j: usize, xs: &Vec<Scalar>) -> Vec<Scalar> {
    // numerator
    let mut num = Univar::from_coefficients_vec(vec![Scalar::one()]);
    let mut den = Scalar::one(); // denominator
    for (k, xk) in xs.iter().enumerate() {
        if k != j {
            num = poly_prod(
                &num,
                &Univar::from_coefficients_vec(vec![-(*xk), Scalar::one()]),
            );
            den *= xs[j] - *xk
        }
    }
    den = den.inverse().unwrap();
    num.coeffs().iter().map(|v| *v * den).collect()
}

pub fn lagrange_interpolate<I>(points: I) -> Univar
where
    I: IntoIterator<Item = (Scalar, Scalar)>,
{
    let (xs, ys): (Vec<Scalar>, Vec<Scalar>) = points.into_iter().unzip();
    let mut res = Univar::from_coefficients_vec(Vec::new());
    for (j, yj) in ys.iter().enumerate() {
        res += &Univar::from_coefficients_vec(
            lagrange_basis(j, &xs)
                .into_iter()
                .map(|v| v * *yj)
                .collect(),
        )
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_secret_is_symmetric() {
        let mut rng = rand::thread_rng();
        let threshold = 40;
        let secret = random_secret(threshold, Scalar::rand(&mut rng), &mut rng);
        for i in 0..(threshold as usize) {
            for j in 0..i {
                assert!(secret.coeffs()[i][j] == secret.coeffs()[j][i])
            }
        }
    }

    #[test]
    fn share_verification() {
        let mut rng = rand::thread_rng();
        let threshold = 10;
        let secret = random_secret(threshold, Scalar::rand(&mut rng), &mut rng);
        let public = public(&secret);
        for i in 0..(threshold * 2) {
            assert!(verify_share(&public, &share(&secret, i.into()), i.into()))
        }
    }

    #[test]
    fn point_verification() {
        let mut rng = rand::thread_rng();
        let threshold = 7;
        let secret = random_secret(threshold, Scalar::rand(&mut rng), &mut rng);
        let public = public(&secret);
        for i in 0..threshold {
            let share = share(&secret, i.into());
            for j in 0..threshold {
                let point = share.evaluate(&j.into());
                assert!(verify_point(&public, j.into(), i.into(), point))
            }
        }
    }

    #[test]
    fn test_multi_share() {
        let participants = 100u32;
        let threshold = 50u32;

        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(1u64);

        let s = Scalar::rand(&mut rng);
        let secret = random_secret(threshold, s, &mut rng);
        let shares = multi_share(&secret, participants as usize);
        let omega = fft::domain(participants as usize).group_gen;

        let mut x = Scalar::one();
        for share in shares.iter() {
            let actual = secret.eval_fst(x);
            for (coeff, actual_coeff) in share.iter().zip(actual.iter()) {
                assert_eq!(coeff, actual_coeff);
            }
            x *= omega;
        }
    }
}
