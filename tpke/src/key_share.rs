use crate::*;
use ark_ec::ProjectiveCurve;
use itertools::Itertools;

#[derive(Clone)]
pub struct PublicKeyShares<E: PairingEngine> {
    pub public_key_shares: Vec<E::G1Affine>, // A_{i, \omega_i}
}

#[derive(Clone)]
pub struct BlindedKeyShares<E: PairingEngine> {
    pub blinding_key: E::G2Affine,                         // [b] H
    pub blinding_key_prepared: E::G2Prepared,              // [b] H
    pub blinded_key_shares: Vec<E::G2Affine>,              // [b] Z_{i, \omega_i}
    pub window_tables: Vec<BlindedKeyShareWindowTable<E>>, // [b*omega_i^-1] Z_{i, \omega_i}
}

impl<E: PairingEngine> BlindedKeyShares<E> {
    pub fn verify_blinding<R: RngCore>(
        &self,
        public_key_shares: &PublicKeyShares<E>,
        rng: &mut R,
    ) -> bool {
        let g = E::G1Affine::prime_subgroup_generator();
        let alpha = E::Fr::rand(rng);
        let alpha_i = generate_random::<_, E>(public_key_shares.public_key_shares.len(), rng);

        let alpha_A_i = E::G1Prepared::from(
            g + public_key_shares
                .public_key_shares
                .iter()
                .zip_eq(alpha_i.iter())
                .map(|(key, alpha)| key.mul(*alpha))
                .sum::<E::G1Projective>()
                .into_affine(),
        );

        let alpha_Z_i = E::G2Prepared::from(
            self.blinding_key
                + self
                    .blinded_key_shares
                    .iter()
                    .zip_eq(alpha_i.iter())
                    .map(|(key, alpha)| key.mul(*alpha))
                    .sum::<E::G2Projective>()
                    .into_affine(),
        );

        E::product_of_pairings(&[
            (E::G1Prepared::from(-g), alpha_Z_i),
            (alpha_A_i, E::G2Prepared::from(self.blinding_key)),
        ]) == E::Fqk::one()
    }
    pub fn get_window_table(
        &self,
        window_size: usize,
        scalar_bits: usize,
        domain_inv: &[E::Fr],
    ) -> Vec<BlindedKeyShareWindowTable<E>> {
        izip!(self.blinded_key_shares.iter(), domain_inv.iter())
            .map(|(key, omega_inv)| BlindedKeyShareWindowTable::<E> {
                window_table: FixedBaseMSM::get_window_table(
                    scalar_bits,
                    window_size,
                    key.mul(-*omega_inv),
                ),
            })
            .collect::<Vec<_>>()
    }
    pub fn multiply_by_omega_inv(&mut self, domain_inv: &[E::Fr]) {
        izip!(self.blinded_key_shares.iter_mut(), domain_inv.iter())
            .for_each(|(key, omega_inv)| *key = key.mul(-*omega_inv).into_affine())
    }
}
#[derive(Clone)]
pub struct BlindedKeyShareWindowTable<E: PairingEngine> {
    pub window_table: Vec<Vec<E::G2Affine>>,
}

#[derive(Clone, Debug)]
pub struct PrivateKeyShare<E: PairingEngine> {
    pub private_key_shares: Vec<E::G2Affine>,
}

impl<E: PairingEngine> PrivateKeyShare<E> {
    pub fn blind(&self, b: E::Fr) -> BlindedKeyShares<E> {
        let blinding_key = E::G2Affine::prime_subgroup_generator().mul(b).into_affine();
        BlindedKeyShares::<E> {
            blinding_key,
            blinding_key_prepared: E::G2Prepared::from(blinding_key),
            blinded_key_shares: self
                .private_key_shares
                .iter()
                .map(|z| z.mul(b).into_affine())
                .collect::<Vec<_>>(),
            window_tables: vec![],
        }
    }
}
