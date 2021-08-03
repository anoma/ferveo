use crate::*;
use ark_ec::ProjectiveCurve;

#[derive(Debug, Clone)]
pub struct DecryptionShare<E: PairingEngine> {
    pub decryptor_index: usize,
    pub decryption_share: E::G1Affine,
}

impl<E: PairingEngine> PrivateDecryptionContext<E> {
    pub fn create_share(&self, ciphertext: &Ciphertext<E>) -> DecryptionShare<E> {
        let decryption_share = ciphertext.nonce.mul(self.b_inv).into_affine();

        DecryptionShare {
            decryptor_index: self.index,
            decryption_share,
        }
    }
    pub fn batch_verify_decryption_shares<R: RngCore>(
        &self,
        ciphertexts: &[Ciphertext<E>],
        shares: &[Vec<DecryptionShare<E>>],
        //ciphertexts_and_shares: &[(Ciphertext<E>, Vec<DecryptionShare<E>>)],
        rng: &mut R,
    ) -> bool {
        let num_ciphertexts = ciphertexts.len();
        let num_shares = shares[0].len();

        // Get [b_i] H for each of the decryption shares
        let blinding_keys = shares[0]
            .iter()
            .map(|D| {
                self.public_decryption_contexts[D.decryptor_index]
                    .blinded_key_shares
                    .blinding_key_prepared
                    .clone()
            })
            .collect::<Vec<_>>();

        // For each ciphertext, generate num_shares random scalars
        let alpha_ij = (0..num_ciphertexts)
            .map(|_| generate_random::<_, E>(num_shares, rng))
            .collect::<Vec<_>>();

        let mut pairings = Vec::with_capacity(num_shares + 1);

        // Compute \sum_i \alpha_{i,j} for each ciphertext j
        let sum_alpha_i = alpha_ij
            .iter()
            .map(|alpha_j| alpha_j.iter().sum::<E::Fr>())
            .collect::<Vec<_>>();

        // Compute \sum_j [ \sum_i \alpha_{i,j} ] U_j
        let sum_U_j = E::G1Prepared::from(
            izip!(ciphertexts.iter(), sum_alpha_i.iter())
                .map(|(c, alpha_j)| c.nonce.mul(*alpha_j))
                .sum::<E::G1Projective>()
                .into_affine(),
        );

        // e(\sum_j [ \sum_i \alpha_{i,j} ] U_j, -H)
        pairings.push((sum_U_j, self.h_inv.clone()));

        let mut sum_D_j = vec![E::G1Projective::zero(); num_shares];

        // sum_D_j = { [\sum_j \alpha_{i,j} ] D_i }
        for (D, alpha_j) in izip!(shares.iter(), alpha_ij.iter()) {
            for (sum_alpha_D_i, Dij, alpha) in izip!(sum_D_j.iter_mut(), D.iter(), alpha_j.iter()) {
                *sum_alpha_D_i += Dij.decryption_share.mul(*alpha);
            }
        }

        // e([\sum_j \alpha_{i,j} ] D_i, B_i)
        for (D_i, B_i) in izip!(sum_D_j.iter(), blinding_keys.iter()) {
            pairings.push((E::G1Prepared::from(D_i.into_affine()), B_i.clone()));
        }

        E::product_of_pairings(&pairings) == E::Fqk::one()
    }
}
