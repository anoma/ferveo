#![allow(unused_imports)]

use super::dh;
use super::nizkp;
use crate::dkg;
use ark_bls12_381::G1Affine;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct Dispute {
    pub dealer: u32,
    pub dealee: u32,
    pub shared_secret: dh::SharedSecret,
    pub nizkp: nizkp::NIZKP_BLS,
}

pub enum DisputeResolution {
    DealerFault,
    ComplainerFault,
}

pub fn send_dispute(
    dkg: &mut dkg::Context,
    vss: &super::sh::Context,
) -> Dispute {
    let mut rng = rand::thread_rng();
    let dealer_dh_key = dkg.participants[vss.dealer as usize].dh_key;
    let (shared_secret, nizkp) =
        dkg.dh_key.decrypter_nizkp(&dealer_dh_key, &mut rng);
    Dispute {
        dealer: vss.dealer,
        dealee: dkg.me as u32,
        shared_secret,
        nizkp,
    }
}

pub fn handle_dispute(
    dkg: &mut dkg::Context,
    dispute: &Dispute,
) -> DisputeResolution {
    if let Some(vss) = dkg.vss.get_mut(&dispute.dealer) {
        {
            let dealer = &dkg.participants[dispute.dealer as usize]; //TODO: index is untrusted input
            let dealee = &dkg.participants[dispute.dealee as usize];

            if !dh::AsymmetricPublicKey::decrypter_nizkp_verify(
                &dealer.dh_key,
                &dealee.dh_key,
                &dispute.shared_secret,
                &dispute.nizkp,
            ) {
                return DisputeResolution::ComplainerFault;
            }
        }
        {
            let dealee = &mut dkg.participants[dispute.dealee as usize];

            use chacha20poly1305::aead::{
                generic_array::GenericArray, NewAead,
            };
            let ciphertext =
                &vss.encrypted_shares.shares[dispute.dealee as usize];
            //dealee.init_share_domain(&dkg.domain); // TODO: lazy evalutate share_domain in a nicer way
            let plaintext = crate::syncvss::sh::decrypt(
                &ciphertext,
                &vss.encrypted_shares.commitment,
                &dealee.share_domain,
                &chacha20poly1305::XChaCha20Poly1305::new(
                    &GenericArray::from_slice(&dispute.shared_secret.to_key()),
                ),
            );
            let result = match plaintext {
                Ok(p) => {
                    vss.state = crate::syncvss::sh::State::Failure;
                    DisputeResolution::ComplainerFault
                }
                Err(e) => DisputeResolution::DealerFault,
            };
        }
    }
    DisputeResolution::ComplainerFault
}
