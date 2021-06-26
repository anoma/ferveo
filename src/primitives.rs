use crate::*;

pub mod keypair;
pub use keypair::*;

pub mod nizkp;
pub use nizkp::*;

pub fn fast_multiexp<Projective: ProjectiveCurve>(
    scalars: &[Projective::ScalarField],
    base: Projective,
) -> Vec<Projective::Affine> {
    let window_size = FixedBaseMSM::get_mul_window_size(scalars.len());

    let scalar_bits = Projective::ScalarField::size_in_bits();
    let base_table =
        FixedBaseMSM::get_window_table(scalar_bits, window_size, base);

    let exp = FixedBaseMSM::multi_scalar_mul::<Projective>(
        scalar_bits,
        window_size,
        &base_table,
        scalars,
    );
    Projective::batch_normalization_into_affine(&exp)
}
