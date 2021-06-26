use crate::*;

pub struct Context<E: Engine> {
    pub tau: u32,
    pub ed_key: ed25519::Keypair,
    pub session_keypair: E::SessionKeypair,
    pub params: Params,
    pub participants: Vec<Participant<E>>,
    pub vss: BTreeMap<u32, E::VSS>,
    pub domain: ark_poly::Radix2EvaluationDomain<E::Scalar>,
    pub state: DKGState<E>,
    pub me: usize,
    pub final_state: Option<DistributedKeyShares<E::Scalar>>,
}

impl<E> Context<E>
where
    E: Engine,
{
    pub fn new<R: Rng>(
        tau: u32,
        ed_key: ed25519::Keypair,
        params: &Params,
        rng: &mut R,
    ) -> Result<Self> {
        use ark_std::UniformRand;
        let domain = ark_poly::Radix2EvaluationDomain::<E::Scalar>::new(
            params.total_weight as usize,
        )
        .ok_or_else(|| anyhow!("unable to construct domain"))?;

        Ok(Self {
            tau,
            ed_key,
            session_keypair: E::new_session_keypair(rng),
            params: *params,
            participants: vec![],
            vss: BTreeMap::new(),
            domain,
            state: DKGState::<E>::Init {
                participants: vec![],
            },
            me: 0, // TODO: invalid value
            final_state: None,
        })
    }
    pub fn final_key(&self) -> E::PublicKey {
        self.vss
            .iter()
            .filter_map(|(_, vss)| {
                if let VSSState::Success { final_secret } = vss.state() {
                    Some(final_secret.into_projective())
                } else {
                    None
                }
            })
            .sum::<<E::PublicKey as AffineCurve>::Projective>()
            .into_affine()
    }

    pub fn announce(&self, stake: u64) -> SignedMessage {
        SignedMessage::new(
            &Message::<E> {
                tau: self.tau,
                payload: MessagePayload::Announce {
                    stake,
                    session_key: E::session_key_public(&self.session_keypair),
                },
            },
            &self.ed_key,
        )
    }
    pub fn deal_if_turn<R: Rng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Option<SignedMessage>> {
        let mut initial_phase_weight = 0u32;
        for (i, p) in self.participants.iter().enumerate() {
            initial_phase_weight += p.weight;
            if initial_phase_weight
                >= self.params.total_weight - self.params.security_threshold
            {
                if i >= self.me {
                    return Ok(Some(self.deal(rng)?));
                } else {
                    return Ok(None);
                }
            }
        }
        Ok(None)
    }

    pub fn deal<R: Rng>(&mut self, rng: &mut R) -> Result<SignedMessage> {
        use ark_std::UniformRand;

        let vss = E::VSS::new(&E::Scalar::rand(rng), &self, rng)?;

        let dealing = vss.deal();
        self.vss.insert(self.me as u32, vss);

        Ok(SignedMessage::new(
            &Message::<E> {
                tau: self.tau,
                payload: MessagePayload::<E>::VSS(dealing),
            },
            &self.ed_key,
        ))
    }
    pub fn partition_domain(&mut self) -> Result<()> {
        if let DKGState::Init { participants } = &mut self.state {
            // Sort participants from greatest to least stake
            participants.sort_by(|a, b| b.stake.cmp(&a.stake));
        }
        //TODO: the borrow checker demands this immutable borrow
        if let DKGState::Init { participants } = &self.state {
            // Compute the total amount staked
            let total_stake: f64 = participants
                .iter()
                .map(|p| p.stake as f64)
                .sum::<f64>()
                .into();

            // Compute the weight of each participant rounded down
            let mut weights = participants
                .iter()
                .map(|p| {
                    ((self.params.total_weight as f64) * p.stake as f64
                        / total_stake)
                        .floor() as u32
                })
                .collect::<Vec<u32>>();

            // Add any excess weight to the largest weight participants
            let adjust_weight = self
                .params
                .total_weight
                .checked_sub(weights.iter().sum())
                .ok_or_else(|| anyhow!("adjusted weight negative"))?
                as usize;
            for i in &mut weights[0..adjust_weight] {
                *i += 1;
            }

            // total_weight is allocated among all participants
            assert_eq!(weights.iter().sum::<u32>(), self.params.total_weight);

            let mut allocated_weight = 0usize;
            let mut domain_element = E::Scalar::one();
            for (participant, weight) in participants.iter().zip(weights) {
                let share_range =
                    allocated_weight..allocated_weight + weight as usize;
                let mut share_domain = Vec::with_capacity(weight as usize);
                for _ in 0..weight {
                    share_domain.push(domain_element);
                    domain_element *= self.domain.group_gen;
                }
                self.participants.push(Participant {
                    ed_key: participant.ed_key,
                    session_key: participant.session_key.clone(),
                    weight,
                    share_range,
                });
                allocated_weight = allocated_weight
                    .checked_add(weight as usize)
                    .ok_or_else(|| anyhow!("allocated weight overflow"))?;
            }
            self.me = self
                .find_by_key(&self.ed_key.public)
                .ok_or_else(|| anyhow!("self not found"))?;
        }
        Ok(())
    }
    pub fn finish_announce(&mut self) -> Result<(), anyhow::Error> {
        self.partition_domain()?;
        self.state = DKGState::Sharing {
            finalized_weight: 0u32,
        };
        Ok(())
    }
    //TODO: this is not a good workaround for finding dealer from ed_key
    pub fn find_by_key(&self, ed_key: &ed25519::PublicKey) -> Option<usize> {
        self.participants.iter().position(|p| p.ed_key == *ed_key)
    }

    pub fn handle_announce(
        &mut self,
        signer: &ed25519::PublicKey,
        stake: u64,
        session_key: E::SessionKey,
    ) -> Result<Option<SignedMessage>> {
        if let DKGState::Init { participants } = &mut self.state {
            participants.push(ParticipantBuilder {
                ed_key: *signer,
                session_key,
                stake,
            });
        }
        Ok(None)
    }
    pub fn handle_vss(
        &mut self,
        signer: &ed25519::PublicKey,
        dealing: &E::DealingMsg,
    ) -> Result<Option<SignedMessage>> {
        if let DKGState::Sharing { finalized_weight } = self.state {
            let dealer = self.find_by_key(signer).ok_or_else(|| {
                anyhow!("received dealing from unknown dealer")
            })? as u32;
            if self.vss.contains_key(&dealer) {
                return Err(anyhow!("Repeat dealer {}", dealer));
            }
            let vss = E::VSS::recv(dealer, dealing, self)?;
            self.vss.insert(dealer, vss);
        }
        Ok(None)
    }

    pub fn handle_message(
        &mut self,
        msg: &SignedMessage,
    ) -> Result<Option<SignedMessage>> {
        let signer = &msg.signer;
        let msg: Message<E> = msg.verify()?;

        if msg.tau != self.tau {
            return Err(anyhow!(
                "wrong tau={}, expected tau={}",
                msg.tau,
                self.tau
            ));
        }
        match msg.payload {
            MessagePayload::Announce { stake, session_key } => {
                self.handle_announce(signer, stake, session_key)
            }
            MessagePayload::VSS(vss) => self.handle_vss(signer, &vss),
            _ => E::handle_other(self, signer, &msg.payload),
        }
    }
}
