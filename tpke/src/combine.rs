use crate::*;
use ark_ec::ProjectiveCurve;

impl<E: PairingEngine> PrivateDecryptionContext<E> {
    pub fn prepare_combine(&self, shares: &[DecryptionShare<E>]) -> Vec<E::G2Prepared> {
        let mut domain = vec![];
        let mut N_0 = E::Fr::one();
        for D_i in shares.iter() {
            domain.extend(
                self.public_decryption_contexts[D_i.decryptor_index]
                    .domain
                    .iter(),
            );
            N_0 *= self.public_decryption_contexts[D_i.decryptor_index].lagrange_N_0;
        }
        let s = SubproductDomain::<E::Fr>::new(domain);
        let mut lagrange = s.inverse_lagrange_coefficients();
        ark_ff::batch_inversion_and_mul(&mut lagrange, &N_0);
        let mut start = 0usize;
        shares
            .iter()
            .map(|D_i| {
                let decryptor = &self.public_decryption_contexts[D_i.decryptor_index];
                let end = start + decryptor.domain.len();
                let lagrange_slice = &lagrange[start..end];
                start = end;
                E::G2Prepared::from(
                    izip!(
                        lagrange_slice.iter(),
                        decryptor.blinded_key_shares.blinded_key_shares.iter() //decryptor.blinded_key_shares.window_tables.iter()
                    )
                    .map(|(lambda, blinded_key_share)| blinded_key_share.mul(*lambda))
                    /*.map(|(lambda, base_table)| {
                        FixedBaseMSM::multi_scalar_mul::<E::G2Projective>(
                            self.scalar_bits,
                            self.window_size,
                            &base_table.window_table,
                            &[*lambda],
                        )[0]
                    })*/
                    .sum::<E::G2Projective>()
                    .into_affine(),
                )
            })
            .collect::<Vec<_>>()
    }
    pub fn share_combine(
        &self,
        ciphertext: &Ciphertext<E>,
        shares: &[DecryptionShare<E>],
        prepared_key_shares: &[E::G2Prepared],
    ) -> E::Fqk {
        let mut pairing_product: Vec<(E::G1Prepared, E::G2Prepared)> = vec![];

        for (D_i, blinded_key_share) in izip!(shares, prepared_key_shares.iter()) {
            // e(D_i, [b*omega_i^-1] Z_{i,omega_i})
            pairing_product.push((
                E::G1Prepared::from(D_i.decryption_share),
                blinded_key_share.clone(),
            ));
        }
        E::product_of_pairings(&pairing_product)
    }
}

#[cfg(test)]
mod tests {

    type E = ark_bls12_381::Bls12_381;
    type Fr = <ark_bls12_381::Bls12_381 as ark_ec::PairingEngine>::Fr;

    #[test]
    fn test_lagrange() {
        use ark_ff;
        use ark_poly::EvaluationDomain;
        use ark_std::One;
        let fft_domain = ark_poly::Radix2EvaluationDomain::<Fr>::new(500).unwrap();

        let mut domain = Vec::with_capacity(500);
        let mut point = Fr::one();
        for _ in 0..500 {
            domain.push(point);
            point *= fft_domain.group_gen;
        }
        let mut N_0 = Fr::one();
        let mut lagrange_N_0 = domain.iter().product::<Fr>();
        if domain.len() % 2 == 1 {
            lagrange_N_0 = -lagrange_N_0;
        }
        let s = crate::subproductdomain::SubproductDomain::<Fr>::new(domain);
        let mut lagrange = s.inverse_lagrange_coefficients();
        ark_ff::batch_inversion_and_mul(&mut lagrange, &lagrange_N_0);
    }
}
