#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]

use crate::poly;

use bls12_381::{G1Projective, Scalar};
use nalgebra::base::DVector;
use std::collections::HashSet;

pub struct Context {
    C: poly::Public,           // the public polynomial
    c: u32,                    // counter for `reconstruct-share` messages
    d: u32,                    // index of the dealer's public key in `p`
    i: u32,                    // index of this node's public key in `p`
    n: u32,                    // number of nodes in the setup
    S: HashSet<(u32, Scalar)>, // set of node-index - share pairs.
    s: Scalar,                 // the share for this node
    t: u32,                    // threshold
    tau: u32,                  // session identifier
}

// Scalar exponentiation by u64. `exp(x, y) = x^y`
fn scalar_exp_u64<T: Into<u64>>(x: Scalar, y: T) -> Scalar {
    x.pow(&[u64::to_le(y.into()), 0, 0, 0])
}

impl Context {
    /* Initialize node with
    dealer index `d`,
    node index `i`,
    participant node public keys `p`,
    threshold `t`,
    and session identifier `tau`. */
    pub fn init(
        C: poly::Public, // the public polynomial
        d: u32,          // index of the dealer's public key in `p`
        i: u32,          // index of this node's public key in `p`
        n: u32,
        s: Scalar,       // the share for this node
        t: u32,          // threshold
        tau: u32,        // session identifier
    ) -> Self {
        if n <= i {
            panic!(
                "Cannot initialize node with index `{}` with fewer than \
                   `{}` participant node public keys.",
                i,
                i + 1
            )
        }
        if n <= d {
            panic!(
                "Cannot set dealer index to `{}` with fewer than \
                   `{}` participant node public keys.",
                d,
                d + 1
            )
        }
        if n < t {
            panic!(
                "Cannot set threshold to `{t}` with fewer than \
                   `{t}` participant node public keys.",
                t = t
            )
        }

        let c = 0;
        let S = HashSet::new();

        Context {
            C,
            c,
            d,
            i,
            n,
            S,
            s,
            t,
            tau,
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
        let lhs = G1Projective::generator() * sigma;
        let rhs = (0..=self.t)
            .map(|j| self.C[(j as usize, 0)] * scalar_exp_u64(m.into(), j))
            .sum();
        if lhs == rhs {
            self.S.insert((m, sigma));
            self.c += 1;
            if self.c == self.t + 1 {
                // the points to use for lagrange interpolation
                let points =
                    self.S.iter().map(|(m, s)| (u64::from(*m).into(), *s));
                let z = poly::lagrange_interpolate(points);
                let z_i = poly::eval_share(&z, Scalar::zero());
                Some(z_i)
            } else {
                None
            }
        } else {
            None
        }
    }
}
