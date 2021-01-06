#![allow(clippy::many_single_char_names)]
#![allow(clippy::too_many_arguments)]


use crate::poly;

use bls12_381::{G1Projective, Scalar};
use nalgebra::base::DVector;
use std::collections::HashSet;

/* Initialize the share protocol, generating a secret polynomial,
a public polynomial, and a share for each node.
Only the dealer needs to run this step. */
pub fn initialize<R: rand::Rng + Sized>(
    rng: &mut R,
    t: u32,    // threshold
    n: u32,    // number of nodes
    s: Scalar, // secret
) -> (poly::Secret, poly::Public, Vec<poly::Share>) {
    let mut secret_poly = poly::random_secret(t, rng);
    secret_poly[(0, 0)] = s;
    let public_poly = poly::public(&secret_poly);
    let shares = (0..n).map(|j| poly::share(&secret_poly, j)).collect();
    (secret_poly, public_poly, shares)
}

/* Receive a share from the dealer.
If the share is consistent with the public polynomial,
then generate a secret for each node. */
pub fn receive_share(
    n: u32, // number of nodes
    i: u32, // the node index
    public_poly: poly::Public,
    share: poly::Share,
) -> Option<Vec<Scalar>> {
    if poly::verify_share(&public_poly, &share, i) {
        let secrets = (0..n)
            .map(|j| poly::eval_share(&share, u64::from(j).into()))
            .collect();
        Some(secrets)
    } else {
        None
    }
}

/* Receive an echo secret from another node.
If the secret is consistent with the public polynomial,
the secret is stored in the set, and the echo count is incremented.
If it is possible to recover a share from the secrets,
then a new ready secret is generated for each node. */
pub fn receive_echo_secret(
    t: u32, // threshold
    n: u32, // number of nodes
    i: u32, // the index of the receiving node
    public_poly: poly::Public,
    secrets: &mut HashSet<(u32, Scalar)>,
    echo_count: &mut u32,
    ready_count: u32,
    m: u32, // the index of the sender node
    secret: Scalar,
) -> Option<Vec<Scalar>> {
    if poly::verify_point(&public_poly, i, m, secret) {
        secrets.insert((m, secret));
        *echo_count += 1;
        if (*echo_count == num::integer::div_ceil(n + t + 1, 2))
            & (ready_count < t + 1)
        {
            // the points to use for lagrange interpolation
            let points = secrets
                .iter()
                .map(|(m, s)| (u64::from(*m).into(), *s))
                .collect();
            let points = DVector::from_vec(points);
            let share = poly::lagrange_interpolate(&points);
            (0..n)
                .map(|j| poly::eval_share(&share, u64::from(j).into()))
                .collect::<Vec<Scalar>>()
                .into()
        } else {
            None
        }
    } else {
        None
    }
}

/* Receive a ready secret from another node.
If the secret is consistent with the public polynomial,
the secret is stored in the set, and the ready count is incremented.
Returns the shared secret if possible.
Otherwise, if it is possible to recover a share from the secrets,
then a new ready secret is generated for each node. */
pub fn receive_ready_secret(
    t: u32, // threshold
    n: u32, // number of nodes
    f: u32, // the failure threshold
    i: u32, // the index of the receiving node
    public_poly: poly::Public,
    secrets: &mut HashSet<(u32, Scalar)>,
    echo_count: u32,
    ready_count: &mut u32,
    m: u32, // the index of the sender node
    secret: Scalar,
) -> (Option<Scalar>, Option<Vec<Scalar>>) {
    if poly::verify_point(&public_poly, i, m, secret) {
        secrets.insert((m, secret));
        *ready_count += 1;
        if (echo_count < num::integer::div_ceil(n + t + 1, 2))
            && (*ready_count == t + 1)
        {
            // the points to use for lagrange interpolation
            let points = secrets
                .iter()
                .map(|(m, s)| (u64::from(*m).into(), *s))
                .collect();
            let points = DVector::from_vec(points);
            let share = poly::lagrange_interpolate(&points);
            let ready_secrets = (0..n)
                .map(|j| poly::eval_share(&share, u64::from(j).into()))
                .collect::<Vec<Scalar>>();
            (None, Some(ready_secrets))
        } else if *ready_count == n - t - f {
            // the points to use for lagrange interpolation
            let points = secrets
                .iter()
                .map(|(m, s)| (u64::from(*m).into(), *s))
                .collect();
            let points = DVector::from_vec(points);
            let share = poly::lagrange_interpolate(&points);
            let shared_secret = poly::eval_share(&share, Scalar::zero());
            (Some(shared_secret), None)
        } else {
            (None, None)
        }
    } else {
        (None, None)
    }
}

// Scalar exponentiation by u64. `exp(x, y) = x^y`
fn scalar_exp_u64(x: Scalar, y: u64) -> Scalar {
    x.pow(&[u64::to_le(y), 0, 0, 0])
}

/* Receive a secret from another node and attempt to reconstruct a share.
If the secret is consistent with the public polynomial,
the secret is stored in the set, and the count is incremented. */
pub fn reconstruct_share(
    t: u32, // threshold
    public_poly: poly::Public,
    secrets: &mut HashSet<(u32, Scalar)>,
    count: &mut u32,
    m: u32, // the index of the sender node
    secret: Scalar,
) -> Option<Scalar> {
    let lhs = G1Projective::generator() * secret;
    let rhs = (0..=t)
        .map(|j| {
            public_poly[(j as usize, 0)]
                * scalar_exp_u64(u64::from(m).into(), j.into())
        })
        .sum();
    if lhs == rhs {
        secrets.insert((m, secret));
        *count += 1;
        if *count == t + 1 {
            // the points to use for lagrange interpolation
            let points = secrets
                .iter()
                .map(|(m, s)| (u64::from(*m).into(), *s))
                .collect();
            let points = DVector::from_vec(points);
            let share = poly::lagrange_interpolate(&points);
            poly::eval_share(&share, Scalar::zero()).into()
        } else {
            None
        }
    } else {
        None
    }
}
