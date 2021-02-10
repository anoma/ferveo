#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]

use crate::poly;

use ark_bls12_381::{Fr, G1Projective};
use ark_ec::ProjectiveCurve;
use ark_ff::Field;
use ark_poly::{Polynomial, Radix2EvaluationDomain};
use num::Zero;
use std::collections::HashSet;

use crate::hybridvss::params::Params;

type Scalar = Fr;

pub struct Context {
    C: poly::Public,                    // the public polynomial
    c: u32, // counter for `reconstruct-share` messages
    domain: Radix2EvaluationDomain<Fr>, // FFT domain (group_gen, log_size_of_group, size)
    params: Params,
    S: HashSet<(Scalar, Scalar)>, // set of node-index - share pairs.
    s: Scalar,                    // the share for this node
}

fn mul_g1proj(lhs: G1Projective, rhs: Scalar) -> G1Projective {
    let mut lhs = lhs;
    lhs *= rhs;
    lhs
}

// Scalar exponentiation by u64. `exp(x, y) = x^y`
fn scalar_exp_u64(x: Scalar, y: u64) -> Scalar {
    x.pow([y])
}

// Scalar exponentiation by u32. `exp(x, y) = x^y`
fn scalar_exp_u32(x: Scalar, y: u32) -> Scalar {
    scalar_exp_u64(x, y.into())
}

impl Context {
    pub fn init(
        params: Params,
        C: poly::Public, // the public polynomial
        domain: Radix2EvaluationDomain<Fr>,
        s: Scalar, // the share for this node
    ) -> Self {
        let c = 0;
        let S = HashSet::new();
        Context {
            C,
            c,
            domain,
            params,
            S,
            s,
        }
    }

    pub fn reconstruct(&self) -> Scalar {
        self.s
    }

    pub fn reconstruct_share(
        &mut self,
        m: u32,
        sigma: Scalar,
    ) -> Option<Scalar> {
        let lhs = mul_g1proj(G1Projective::prime_subgroup_generator(), sigma);
        let rhs = (0..=self.params.t)
            .map(|j| {
                mul_g1proj(
                    self.C[j as usize][0].into(),
                    scalar_exp_u32(self.domain.group_gen, m * j), // omega^((k + m) * j)
                )
            })
            .sum::<G1Projective>();
        if lhs == rhs {
            let wm = scalar_exp_u32(self.domain.group_gen, m); // omega^m
            self.S.insert((wm, sigma));
            self.c += 1;
            if self.c == self.params.t + 1 {
                // the points to use for lagrange interpolation
                let points = self.S.clone();
                let z = poly::lagrange_interpolate(points);
                let z_i = z.evaluate(&Scalar::zero());
                Some(z_i)
            } else {
                None
            }
        } else {
            None
        }
    }
}
