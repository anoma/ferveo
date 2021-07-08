#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]

use crate::dkg;

use crate::syncvss::nizkp::NIZKP;
use ark_ec::AffineCurve;
use ark_ec::ProjectiveCurve;
use ark_ff::PrimeField;
use ark_poly::{
    polynomial::univariate::DensePolynomial, polynomial::UVPolynomial,
};
use ark_serialize::*;
use chacha20poly1305::aead::Aead;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct ShareEncryptions {
    #[serde(with = "crate::ark_serde")]
    pub encryptions: Vec<G2Affine>,
}

/// The possible States of a VSS instance
pub enum State<E: Engine> {
    /// The VSS is currently in a Sharing state with weight_ready
    /// of participants signaling Ready for this VSS
    Sharing { weight: u32 },
    /// The VSS has completed Successfully with final secret commitment g^{\phi(0)}
    Success { final_secret: G2Affine },
    /// The VSS has ended in Failure
    Failure,
}

/// The Context of an individual VSS instance as either the Dealer or the Dealee
pub struct VSSContext {
    pub dealer: u32,
    pub pvss: PVSS,
    pub state: State,
}

/// The dealer posts the EncryptedShares to the blockchain to initiate the VSS

impl<Affine> VSSContext<Affine>
where
    Affine: AffineCurve,
{
    pub fn new_send<R: rand::Rng + rand::CryptoRng + Sized>(
        s: &Affine::ScalarField,
        dkg: &dkg::Context,
        rng: &mut R,
    ) -> Result<Self> {
        use ark_poly::Polynomial;
        let mut phi = DensePolynomial::<Affine::ScalarField>::rand(
            dkg.params.security_threshold as usize,
            rng,
        );
        phi.coeffs[0] = *s;

        let evals = phi.evaluate_over_domain_by_ref(dkg.domain);

        // commitment to coeffs
        let coeffs = crate::syncvss::fast_multiexp(
            &evals.evals,
            Affine::Projective::prime_subgroup_generator(),
        );

        let shares = dkg
            .participants
            .iter()
            .map(|participant| {
                let share_range = participant.share_range.clone();

                let encryptions = crate::syncvss::fast_multiexp(
                    &evals.evals[share_range],
                    Affine::Projective::prime_subgroup_generator(),
                );

                ShareEncryptions { encryptions }
            })
            .collect::<Vec<ShareEncryptions>>();

        //phi.zeroize(); // TODO zeroize?

        let u_hat = G2Affine::prime_subgroup_generator().mul(*s).into(); //TODO: new base

        let sigma = (
            G2Affine::prime_subgroup_generator().mul(*s).into(),
            G2Affine::prime_subgroup_generator()
                .mul(dkg.signing_key)
                .into(),
        );
        let vss = Context {
            dealer: dkg.me as u32,
            pvss: PVSS {
                coeffs,
                u_hat,
                shares,
                sigma,
            },
            state: State::Sharing { weight_ready: 0u32 },
        };

        Ok(vss)
    }
    pub fn verify_pvss(
        dealer: u32,
        pvss: &PVSS,
        dkg: &mut dkg::Context,
    ) -> Result<Context, anyhow::Error> {
        use ark_poly::EvaluationDomain;
        let me = &dkg.participants[dkg.me as usize];

        if pvss.shares.len() != dkg.participants.len() {
            return Err(anyhow::anyhow!("wrong pvss length"));
        }
        //let adjusted_index =
        //    dkg.me - if dkg.me > dealer as usize { 1 } else { 0 };

        let shares = pvss.shares[dkg.me]
            .encryptions
            .iter()
            .map(|p| p.mul(dkg.decryption_key))
            .collect::<Vec<_>>();

        let mut commitment = pvss
            .coeffs
            .iter()
            .map(|p| p.into_projective())
            .collect::<Vec<_>>();

        dkg.domain.fft_in_place(&mut commitment);

        let commitment =
            G1Projective::batch_normalization_into_affine(&commitment);

        /*let window_size =
                    FixedBaseMSM::get_mul_window_size(commitment.len() + 1);

                let scalar_bits = Scalar::size_in_bits();
                let g_table = FixedBaseMSM::get_window_table(
                    scalar_bits,
                    window_size,
                    G1Affine::prime_subgroup_generator().into_projective(),
                );
                let shares_commitment = FixedBaseMSM::multi_scalar_mul::<G1Projective>(
                    scalar_bits,
                    window_size,
                    &g_table,
                    &local_shares.shares,
                    //&dkg.participants[dkg.me].share_domain,
                );
                let shares_commitment =
                    Projective::batch_normalization_into_affine(&shares_commitment);
        */
        use ark_ec::PairingEngine;

        if Curve::pairing(
            pvss.coeffs[0],
            G2Projective::prime_subgroup_generator(),
        ) != Curve::pairing(
            G1Projective::prime_subgroup_generator(),
            pvss.u_hat,
        ) {
            return Err(anyhow::anyhow!("invalid"));
        }

        dkg.participants.iter().all(|participant| {
            let share_range = participant.share_range.clone();
            pvss.shares[share_range]
                .iter()
                .zip(commitment[share_range].iter())
                .all(|(Y, A)| {
                    Curve::pairing(G1Projective::prime_subgroup_generator(), Y)
                        == Curve::pairing(
                            A,
                            G2Projective::prime_subgroup_generator(),
                        )
                })
        });

        for (i, j) in commitment.iter().zip(shares.iter()) {
            if *i != *j {
                return Err(anyhow::anyhow!("share opening proof invalid"));
            }
        }

        Ok(Context {
            dealer,
            encrypted_shares: encrypted_shares.clone(),
            state: State::Sharing { weight_ready: 0u32 },
            local_shares: local_shares.shares,
            finalize_msg: None,
            ready_msg: vec![],
        })
    }
}
