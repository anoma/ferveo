//use crate::*;

pub fn batch_to_projective<A: ark_ec::AffineCurve>(
    p: &[A],
) -> Vec<A::Projective> {
    p.iter().map(|a| a.into_projective()).collect::<Vec<_>>()
}
