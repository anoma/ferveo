use crate::*;
use ark_ec::PairingEngine;
use ark_std::{end_timer, start_timer};

pub struct PubliclyVerifiableDKG<E>
where
    E: PairingEngine,
{
    pub ed_key: ed25519::Keypair,
    pub params: Params,
    pub pvss_params: PubliclyVerifiableParams<E>,
    pub session_keypair: PubliclyVerifiableKeypair<E>,
    pub participants: Vec<PubliclyVerifiableParticipant<E>>,
    pub vss: BTreeMap<u32, PubliclyVerifiableSS<E>>,
    pub domain: ark_poly::Radix2EvaluationDomain<E::Fr>,
    pub state: DKGState<PubliclyVerifiableAnnouncement<E>>,
    pub me: usize,
    pub local_shares: Vec<E::G2Affine>,
}

impl<E> PubliclyVerifiableDKG<E>
where
    E: PairingEngine,
{
    pub fn new<R: Rng>(
        ed_key: ed25519::Keypair,
        params: Params,
        pvss_params: PubliclyVerifiableParams<E>,
        rng: &mut R,
    ) -> Result<Self> {
        use ark_std::UniformRand;
        let domain = ark_poly::Radix2EvaluationDomain::<E::Fr>::new(
            params.total_weight as usize,
        )
        .ok_or_else(|| anyhow!("unable to construct domain"))?;

        Ok(Self {
            ed_key,
            session_keypair: PubliclyVerifiableKeypair::<E>::new(rng),
            params,
            pvss_params,
            participants: vec![],
            vss: BTreeMap::new(),
            domain,
            state: DKGState::<PubliclyVerifiableAnnouncement<E>>::Init {
                announce_messages: vec![],
            },
            me: 0, // TODO: invalid value
            //final_state: None,
            local_shares: vec![],
        })
    }
    pub fn share<R: Rng>(
        &mut self,
        rng: &mut R,
    ) -> Result<PubliclyVerifiableMessage<E>> {
        use ark_std::UniformRand;
        print_time!("PVSS Sharing");

        let vss =
            PubliclyVerifiableSS::<E>::new(&E::Fr::rand(rng), &self, rng)?;

        let sharing = vss.clone();
        self.vss.insert(self.me as u32, vss);

        Ok(PubliclyVerifiableMessage::Sharing(sharing))
    }

    pub fn aggregate(&mut self) -> PubliclyVerifiableMessage<E> {
        let pvss = PubliclyVerifiableSS::<E>::aggregate(self, &self.vss);
        PubliclyVerifiableMessage::Aggregate(pvss)
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
    pub fn final_key(&self) -> E::G1Affine {
        self.vss
            .iter()
            .map(|(_, vss)| vss.coeffs[0].into_projective())
            .sum::<E::G1Projective>()
            .into_affine()
    }

    pub fn announce(&mut self, stake: u64) -> SignedMessage {
        SignedMessage::sign(
            self.params.tau,
            &PubliclyVerifiableMessage::Announce {
                stake,
                session_key: self.session_keypair.public(),
            },
            &self.ed_key,
        )
    }
    pub fn handle_message(
        &mut self,
        signer: &ed25519::PublicKey,
        payload: PubliclyVerifiableMessage<E>,
    ) -> Result<Option<SignedMessage>> {
        match payload {
            PubliclyVerifiableMessage::Announce { stake, session_key } => {
                if let DKGState::Init { announce_messages } = &mut self.state {
                    announce_messages.push(PubliclyVerifiableAnnouncement {
                        stake,
                        session_key,
                        signer: *signer,
                    });
                }
                Ok(None)
            }
            PubliclyVerifiableMessage::Sharing(sharing) => {
                if let DKGState::Sharing { finalized_weight } = self.state {
                    let dealer = self.find_by_key(signer).ok_or_else(|| {
                        anyhow!("received dealing from unknown dealer")
                    })? as u32;
                    if dealer != self.me as u32 {
                        if self.vss.contains_key(&dealer) {
                            return Err(anyhow!("Repeat dealer {}", dealer));
                        }
                        self.vss.insert(dealer, sharing);
                    }
                }
                Ok(None)
            }
            PubliclyVerifiableMessage::Aggregate(vss) => {
                if let DKGState::Sharing { finalized_weight } = self.state {
                    let minimum_weight = self.params.total_weight
                    //- self.params.failure_threshold
                    - self.params.security_threshold;
                    let (verified_weight, local_shares) =
                        vss.verify_aggregation(&self)?;
                    if verified_weight >= minimum_weight {
                        self.local_shares = local_shares;
                        self.state = DKGState::Success;
                    } else {
                        self.state = DKGState::Sharing {
                            finalized_weight: verified_weight,
                        };
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
pub enum PubliclyVerifiableMessage<E: PairingEngine> {
    Announce {
        stake: u64,
        session_key: PubliclyVerifiablePublicKey<E>,
    },
    #[serde(with = "ark_serde")]
    Sharing(PubliclyVerifiableSS<E>),
    #[serde(with = "ark_serde")]
    Aggregate(PubliclyVerifiableSS<E>),
}

#[derive(Clone, Debug)]
pub struct PubliclyVerifiableParticipant<E: PairingEngine> {
    pub ed_key: ed25519::PublicKey,
    pub session_key: PubliclyVerifiablePublicKey<E>,
    pub weight: u32,
    pub share_range: std::ops::Range<usize>,
}

#[derive(Debug, Clone)]
pub struct PubliclyVerifiableAnnouncement<E: PairingEngine> {
    pub signer: ed25519::PublicKey,
    pub session_key: PubliclyVerifiablePublicKey<E>,
    pub stake: u64,
}

impl<E> Announcement for PubliclyVerifiableAnnouncement<E>
where
    E: PairingEngine,
{
    type Participant = PubliclyVerifiableParticipant<E>;
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
