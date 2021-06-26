use ark_ec::PairingEngine;
use serde::*;

pub type ShareEncryptions<E: PairingEngine> = Vec<E::G2Affine>;

#[derive(Serialize, Deserialize, Clone)]
pub struct PVSS<E: PairingEngine> {
    /// Feldman commitment to the VSS polynomial, F = g^{\phi}
    #[serde(with = "crate::ark_serde")]
    pub coeffs: Vec<E::G1Affine>,

    // \hat{u}_2 = \hat{u}_1^{a_0}
    #[serde(with = "crate::ark_serde")]
    pub u_hat: E::G2Affine,

    // ek_i^{f(\omega_j)}
    #[serde(with = "crate::ark_serde")]
    pub shares: Vec<ShareEncryptions<E>>,

    // Signature of Knowledge
    #[serde(with = "crate::ark_serde")]
    pub sigma: (E::G2Affine, E::G2Affine),
}
