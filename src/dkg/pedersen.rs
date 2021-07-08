use crate::*;

pub struct PedersenDKG<Affine>
where
    Affine: AffineCurve,
{
    pub ed_key: ed25519::Keypair,
    pub params: Params,
    pub session_keypair: AsymmetricKeypair<Affine>,
    pub participants: Vec<PedersenParticipant<Affine>>,
    pub vss: BTreeMap<u32, FeldmanVSS<Affine>>,
    pub domain: ark_poly::Radix2EvaluationDomain<Affine::ScalarField>,
    pub state: DKGState<PedersenAnnouncement<Affine>>,
    pub me: usize,
    pub final_state: Option<DistributedKeyShares<Affine::ScalarField>>,
}

impl<Affine> PedersenDKG<Affine>
where
    Affine: AffineCurve,
{
    pub fn new<R: Rng>(
        ed_key: ed25519::Keypair,
        params: &Params,
        rng: &mut R,
    ) -> Result<Self> {
        use ark_std::UniformRand;
        let domain =
            ark_poly::Radix2EvaluationDomain::<Affine::ScalarField>::new(
                params.total_weight as usize,
            )
            .ok_or_else(|| anyhow!("unable to construct domain"))?;

        Ok(Self {
            ed_key,
            session_keypair: AsymmetricKeypair::<Affine>::new(rng),
            params: *params,
            participants: vec![],
            vss: BTreeMap::new(),
            domain,
            state: DKGState::<PedersenAnnouncement<Affine>>::Init {
                announce_messages: vec![],
            },
            me: 0, // TODO: invalid value
            final_state: None,
        })
    }
    pub fn share<R: Rng>(&mut self, rng: &mut R) -> Result<SignedMessage> {
        use ark_std::UniformRand;

        let vss = FeldmanVSS::<Affine>::new(
            &Affine::ScalarField::rand(rng),
            &self,
            rng,
        )?;

        let sharing = vss.encrypted_shares.clone();
        self.vss.insert(self.me as u32, vss);

        Ok(SignedMessage::sign(
            self.params.tau,
            &PedersenMessage::Sharing(sharing),
            &self.ed_key,
        ))
    }

    //TODO: this is not a good workaround for finding dealer from ed_key
    pub fn find_by_key(&self, ed_key: &ed25519::PublicKey) -> Option<usize> {
        self.participants.iter().position(|p| p.ed_key == *ed_key)
    }
    pub fn finish_announce(&mut self) -> Result<()> {
        if let DKGState::Init { announce_messages } = &mut self.state {
            self.participants =
                partition_domain(&self.params, announce_messages)?;
            self.me = self
                .find_by_key(&self.ed_key.public)
                .ok_or_else(|| anyhow!("self not found"))?;
            self.state = DKGState::Sharing {
                finalized_weight: 0u32,
            };
        }
        Ok(())
    }
    pub fn final_key(&self) -> Affine {
        self.vss
            .iter()
            .filter_map(|(_, vss)| {
                if let VSSState::Success { final_secret } = vss.state {
                    Some(final_secret.into_projective())
                } else {
                    None
                }
            })
            .sum::<Affine::Projective>()
            .into_affine()
    }

    pub fn announce(&mut self, stake: u64) -> SignedMessage {
        SignedMessage::sign(
            self.params.tau,
            &PedersenMessage::Announce {
                stake,
                session_key: self.session_keypair.public(),
            },
            &self.ed_key,
        )
    }
    pub fn handle_message(
        &mut self,
        signer: &ed25519::PublicKey,
        payload: &PedersenMessage<Affine>,
    ) -> Result<Option<SignedMessage>> {
        match payload {
            PedersenMessage::Announce { stake, session_key } => {
                if let DKGState::Init { announce_messages } = &mut self.state {
                    announce_messages.push(PedersenAnnouncement {
                        stake: *stake,
                        session_key: *session_key,
                        signer: *signer,
                    });
                }
                Ok(None)
            }
            PedersenMessage::Sharing(sharing) => {
                if let DKGState::Sharing { finalized_weight } = self.state {
                    let dealer = self.find_by_key(signer).ok_or_else(|| {
                        anyhow!("received dealing from unknown dealer")
                    })? as u32;
                    if dealer != self.me as u32 {
                        if self.vss.contains_key(&dealer) {
                            return Err(anyhow!("Repeat dealer {}", dealer));
                        }
                        let vss = FeldmanVSS::recv(dealer, sharing, self)?;
                        self.vss.insert(dealer, vss);
                    }
                    let ready_msg =
                        PedersenMessage::<Affine>::Ready(FeldmanReadyMsg {
                            dealer,
                        });
                    return Ok(Some(SignedMessage::sign(
                        self.params.tau,
                        &ready_msg,
                        &self.ed_key,
                    )));
                }
                Ok(None)
            }
            PedersenMessage::Ready(ready) => {
                if let DKGState::Sharing { finalized_weight } = self.state {
                    if let Some(vss) = self.vss.get_mut(&ready.dealer) {
                        let signer_weight = self
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
                            >= self.params.total_weight
                                //- self.params.failure_threshold
                                - self.params.security_threshold
                        {
                            if let Some(finalize) = vss.finalize_msg {
                                vss.finalize_msg = None;
                                return Ok(Some(SignedMessage::sign(
                                    self.params.tau,
                                    &PedersenMessage::<Affine>::Finalize(
                                        finalize,
                                    ),
                                    &self.ed_key,
                                )));
                            }
                        }
                    }
                }
                Ok(None)
            }
            PedersenMessage::Finalize(finalize) => {
                if let DKGState::Sharing { finalized_weight } = self.state {
                    let dealer = self.find_by_key(signer).ok_or_else(|| {
                        anyhow!("received finalize from unknown dealer")
                    })? as u32; //TODO: this is not a good workaround for finding dealer from ed_key
                    if let Some(context) = self.vss.get_mut(&dealer) {
                        let minimum_ready_weight = self.params.total_weight
                            //- self.params.failure_threshold
                            - self.params.security_threshold;
                        context.handle_finalize(
                            &finalize,
                            minimum_ready_weight,
                            &Affine::prime_subgroup_generator(), //todo
                        )?;
                        // Finalize succeeded
                        let finalized_weight = finalized_weight
                            + self.participants[dealer as usize].weight;
                        if finalized_weight >= minimum_ready_weight {
                            self.state = DKGState::Success;
                        } else {
                            self.state = DKGState::Sharing { finalized_weight };
                        }
                    }
                }
                Ok(None)
            }
            _ => Err(anyhow!("Unknown message type for this DKG engine")),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "")]
pub enum PedersenMessage<Affine: AffineCurve> {
    Announce {
        stake: u64,
        session_key: AsymmetricPublicKey<Affine>,
    },
    Sharing(FeldmanSharingMsg<Affine>),
    Ready(FeldmanReadyMsg),
    Finalize(FeldmanFinalizeMsg<Affine>),
}

#[derive(Clone, Debug)]
pub struct PedersenParticipant<Affine: AffineCurve> {
    pub ed_key: ed25519::PublicKey,
    pub session_key: AsymmetricPublicKey<Affine>,
    pub weight: u32,
    pub share_range: std::ops::Range<usize>,
}

#[derive(Debug, Clone)]
pub struct PedersenAnnouncement<Affine: AffineCurve> {
    pub signer: ed25519::PublicKey,
    pub session_key: AsymmetricPublicKey<Affine>,
    pub stake: u64,
}

impl<Affine> Announcement for PedersenAnnouncement<Affine>
where
    Affine: AffineCurve,
{
    type Participant = PedersenParticipant<Affine>;
    fn stake(&self) -> u64 {
        self.stake
    }

    fn participant(
        &self,
        weight: u32,
        share_range: std::ops::Range<usize>,
    ) -> Self::Participant {
        Self::Participant {
            ed_key: self.signer,
            session_key: self.session_key,
            weight,
            share_range,
        }
    }
}
