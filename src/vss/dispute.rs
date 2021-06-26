#![allow(unused_imports)]

use crate::*;

#[derive(Serialize, Deserialize, Clone)]
pub struct Dispute<Affine>
where
    Affine: AffineCurve,
{
    pub dealer: u32,
    pub dealee: u32,
    pub shared_secret: SharedSecret<Affine>,
    pub nizkp: NIZKP<Affine>,
}

pub enum DisputeResolution {
    DealerFault,
    ComplainerFault,
}

impl<Affine> Dispute<Affine>
where
    Affine: AffineCurve,
{
    pub fn send_dispute(
        dkg: &mut Context<PedersenDKG<Affine>>,
        dealer: u32,
    ) -> Self {
        let mut rng = rand::thread_rng();
        let dealer_dh_key = dkg.participants[dealer as usize].session_key;
        let (shared_secret, nizkp) = dkg
            .session_keypair
            .decrypter_nizkp(&dealer_dh_key, &mut rng);
        Self {
            dealer,
            dealee: dkg.me as u32,
            shared_secret,
            nizkp,
        }
    }

    pub fn handle_dispute(
        &self,
        dkg: &mut Context<PedersenDKG<Affine>>,
    ) -> DisputeResolution {
        if let Some(vss) = dkg.vss.get_mut(&self.dealer) {
            {
                let dealer = &dkg.participants[self.dealer as usize]; //TODO: index is untrusted input
                let dealee = &dkg.participants[self.dealee as usize];

                if !AsymmetricPublicKey::decrypter_nizkp_verify(
                    &dealer.session_key,
                    &dealee.session_key,
                    &self.shared_secret,
                    &self.nizkp,
                ) {
                    return DisputeResolution::ComplainerFault;
                }
            }
            {
                //let dealee = &mut dkg.participants[dispute.dealee as usize];

                use chacha20poly1305::aead::{
                    generic_array::GenericArray, NewAead,
                };
                let ciphertext =
                    &vss.encrypted_shares.shares[self.dealee as usize];
                //dealee.init_share_domain(&dkg.domain); // TODO: lazy evalutate share_domain in a nicer way
                let plaintext = ciphertext.decrypt::<Affine>(
                    &chacha20poly1305::XChaCha20Poly1305::new(
                        &GenericArray::from_slice(&self.shared_secret.to_key()),
                    ),
                );
                let _result = match plaintext {
                    Ok(_) => {
                        vss.state = VSSState::Failure;
                        DisputeResolution::ComplainerFault
                    }
                    Err(_) => DisputeResolution::DealerFault,
                };
            }
        }
        DisputeResolution::ComplainerFault
    }
}
