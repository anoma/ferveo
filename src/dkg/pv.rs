use crate::*;
use ark_ec::PairingEngine;
use ark_std::{end_timer, start_timer};

/// The DKG context that holds all of the local state for participating in the DKG
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
    pub state: DKGState<E>,
    pub me: usize,
    pub local_shares: Vec<E::G2Affine>,
}

impl<E> PubliclyVerifiableDKG<E>
where
    E: PairingEngine,
{
    /// Create a new DKG context to participate in the DKG
    /// Every identity in the DKG is linked to an ed25519 public key;
    /// `ed_key` is the local identity.
    /// `params` contains the parameters of the DKG such as number of shares
    /// `pvss_params` contains the elliptic curve generators that should be used in the PVSS
    /// `rng` is a cryptographic random number generator
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
            state: DKGState::<E>::Init {
                announce_messages: vec![],
            },
            me: 0, // TODO: invalid value
            //final_state: None,
            local_shares: vec![],
        })
    }
    /// Create a new PVSS instance within this DKG session, contributing to the final key
    /// `rng` is a cryptographic random number generator
    /// Returns a PVSS sharing message to post on-chain
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
    /// Aggregate all received PVSS messages into a single message, prepared to post on-chain
    pub fn aggregate(&mut self) -> PubliclyVerifiableMessage<E> {
        let pvss = PubliclyVerifiableSS::<E>::aggregate(self, &self.vss);
        PubliclyVerifiableMessage::Aggregate(pvss)
    }

    /// Converts an ed25519 key to the index of that participant
    //TODO: this is not a good workaround for finding dealer from ed_key
    pub fn find_by_key(&self, ed_key: &ed25519::PublicKey) -> Option<usize> {
        self.participants.iter().position(|p| p.ed_key == *ed_key)
    }

    /// Call `finish_announce` once the Announcement phase is complete
    /// Partitions the share domain among the announced participants
    /// and begins the sharing phase of the DKG
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
    /// Returns the public key generated by the DKG
    pub fn final_key(&self) -> E::G1Affine {
        self.vss
            .iter()
            .map(|(_, vss)| vss.coeffs[0].into_projective())
            .sum::<E::G1Projective>()
            .into_affine()
    }

    /// Create an `Announce` message
    /// `stake`: the amount staked by this participant in the DKG
    /// Returns an Announcement nessage to post on chain
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

    /// Handle a DKG related message posted on chain
    /// `signer` is the ed25519 public key of the sender of the message
    /// `payload` is the content of the message
    pub fn handle_message(
        &mut self,
        signer: &ed25519::PublicKey,
        payload: PubliclyVerifiableMessage<E>,
    ) -> Result<Option<SignedMessage>> {
        match payload {
            PubliclyVerifiableMessage::Announce { stake, session_key } => {
                if let DKGState::Init { announce_messages } = &mut self.state {
                    announce_messages.push(
                        PubliclyVerifiableAnnouncement::<E> {
                            stake,
                            session_key,
                            signer: *signer,
                        },
                    );
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
