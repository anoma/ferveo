pub mod bls;
pub mod dkg;
pub mod hash_to_curve;
pub mod hash_to_field;
pub mod hybriddkg;
pub mod hybridvss;
pub mod msg;
pub mod poly;
pub mod syncvss;

pub use msg::ark_serde;
pub mod fastkzg;
pub mod fastpoly;

pub type Scalar = ark_bls12_381::Fr;
pub type Curve = ark_bls12_381::Bls12_381;

pub type KZG = ark_poly_commit::kzg10::KZG10<
    Curve,
    ark_poly::polynomial::univariate::DensePolynomial<Scalar>,
>;
