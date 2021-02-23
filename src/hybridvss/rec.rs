#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]

use crate::poly;

use ark_bls12_381::{Fr, G1Projective};
use ark_ec::ProjectiveCurve;
use ark_ff::Field;
use ark_poly::polynomial::Polynomial;
use num::Zero;
use std::collections::HashSet;

use crate::hybridvss::params::Params;

type Scalar = Fr;

pub struct Context {
    C: poly::Public, // the public polynomial
    c: u32,          // counter for `reconstruct-share` messages
    i: u32,          // the index for this node
    params: Params,
    S: HashSet<(u32, Scalar)>, // set of node-index - share pairs.
    s: Scalar,                 // the share for this node
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
        i: u32,          // index of this node
        s: Scalar,       // the share for this node
    ) -> Self {
        let c = 0;
        let S = HashSet::new();

        Context {
            C,
            c,
            i,
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
                    scalar_exp_u32(m.into(), j),
                )
            })
            .sum::<G1Projective>();
        if lhs == rhs {
            self.S.insert((m, sigma));
            self.c += 1;
            if self.c == self.params.t + 1 {
                // the points to use for lagrange interpolation
                let points =
                    self.S.iter().map(|(m, s)| (u64::from(*m).into(), *s));
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
