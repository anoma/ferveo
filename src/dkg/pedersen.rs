use crate::*;

pub struct PedersenDKG<Affine>
where
    Affine: AffineCurve,
{
    _phantom: std::marker::PhantomData<Affine>,
}

impl<Affine> Engine for PedersenDKG<Affine>
where
    Affine: AffineCurve,
{
    type SessionKeypair = AsymmetricKeypair<Affine>;
    type SessionKey = AsymmetricPublicKey<Affine>;
    type VSS = FeldmanVSS<Affine>;
    type DealingMsg = EncryptedShares<Affine>;
    type ReadyMsg = FeldmanReadyMsg;
    type FinalizeMsg = FeldmanFinalizeMsg<Affine>;
    type Scalar = Affine::ScalarField;
    type PublicKey = Affine;

    fn new_session_keypair<R: Rng>(rng: &mut R) -> Self::SessionKeypair {
        AsymmetricKeypair::<Affine>::new(rng)
    }
    fn session_key_public(
        session_keypair: &Self::SessionKeypair,
    ) -> Self::SessionKey {
        session_keypair.public()
    }
    fn handle_other(
        dkg: &mut Context<Self>,
        signer: &ed25519::PublicKey,
        payload: &MessagePayload<Self>,
    ) -> Result<Option<SignedMessage>> {
        match payload {
            MessagePayload::Ready(ready) => {
                if let DKGState::Sharing { finalized_weight } = dkg.state {
                    if let Some(vss) = dkg.vss.get_mut(&ready.dealer) {
                        let signer_weight = dkg
                            .participants
                            .iter()
                            .find(|p| p.ed_key == *signer)
                            .ok_or_else(|| {
                                anyhow!(
                                    "received ready from unknown signer" //TODO: should not be error, but silent ignore?
                                )
                            })?
                            .weight; //TODO: also this is not a good workaround for finding signer from ed_key
                        let new_weight =
                            vss.handle_ready(&signer, &ready, signer_weight)?;
                        if new_weight
                            >= dkg.params.total_weight
                                //- self.params.failure_threshold
                                - dkg.params.security_threshold
                        {
                            if let Some(finalize) = vss.finalize_msg {
                                vss.finalize_msg = None;
                                return Ok(Some(SignedMessage::new(
                                    &Message::<Self> {
                                        tau: dkg.tau,
                                        payload: MessagePayload::Finalize(
                                            finalize,
                                        ),
                                    },
                                    &dkg.ed_key,
                                )));
                            }
                        }
                    }
                }
                Ok(None)
            }
            MessagePayload::Finalize(finalize) => {
                if let DKGState::Sharing { finalized_weight } = dkg.state {
                    let dealer = dkg.find_by_key(signer).ok_or_else(|| {
                        anyhow!("received finalize from unknown dealer")
                    })? as u32; //TODO: this is not a good workaround for finding dealer from ed_key
                    if let Some(context) = dkg.vss.get_mut(&dealer) {
                        let minimum_ready_weight = dkg.params.total_weight
                            //- self.params.failure_threshold
                            - dkg.params.security_threshold;
                        context.handle_finalize(
                            &finalize,
                            minimum_ready_weight,
                            &Affine::prime_subgroup_generator(), //todo
                        )?;
                        // Finalize succeeded
                        let finalized_weight = finalized_weight
                            + dkg.participants[dealer as usize].weight;
                        if finalized_weight >= minimum_ready_weight {
                            dkg.state = DKGState::Success;
                        } else {
                            dkg.state = DKGState::Sharing { finalized_weight };
                        }
                    }
                }
                Ok(None)
            }
            _ => Err(anyhow!("Unknown message type for this DKG engine")),
        }
    }
}
