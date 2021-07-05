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
    // pub final_state: Option<DistributedKeyShares<E::G2Affine::ScalarField>>,
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
        })
    }
    pub fn share<R: Rng>(&mut self, rng: &mut R) -> Result<SignedMessage> {
        use ark_std::UniformRand;
        print_time!("PVSS Sharing");

        let vss =
            PubliclyVerifiableSS::<E>::new(&E::Fr::rand(rng), &self, rng)?;

        let sharing = vss.clone();
        self.vss.insert(self.me as u32, vss);

        Ok(SignedMessage::sign(
            self.params.tau,
            &PubliclyVerifiableMessage::Sharing(sharing),
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
                        print_time!("PVSS verify");
                        sharing.verify(self)?;
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
                    let verified_weight = vss.verify_aggregation(&self)?;
                    if verified_weight >= minimum_weight {
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

/*encryption_key: G2Affine::prime_subgroup_generator()
.into_projective()
.mul(self.decryption_key.inverse().unwrap())
.into_affine(),
verification_key: G2Affine::prime_subgroup_generator()
.into_projective()
.mul(&self.signing_key.inverse().unwrap())
.into_affine(),*/

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "")]
pub enum PubliclyVerifiableMessage<E: PairingEngine> {
    Announce {
        stake: u64,
        session_key: PubliclyVerifiablePublicKey<E>,
    },
    Sharing(PubliclyVerifiableSS<E>),
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

#[test]
pub fn test_pvdkg_bls() {
    test_pvdkg::<ark_bls12_381::Bls12_381>();
}

#[cfg(test)]
pub fn test_pvdkg<E: PairingEngine>() {
    use ark_ec::{AffineCurve, ProjectiveCurve};
    let rng = &mut ark_std::test_rng();

    let params = Params {
        tau: 0u64,
        failure_threshold: 1,
        security_threshold: 8192 / 3,
        total_weight: 8192,
    };

    let pvss_params = PubliclyVerifiableParams::<E> {
        g_1: E::G1Projective::prime_subgroup_generator(),
        u_hat_1: E::G2Affine::prime_subgroup_generator(),
    };

    for _ in 0..1 {
        let mut contexts = vec![];
        for _ in 0..150 {
            contexts.push(
                PubliclyVerifiableDKG::<E>::new(
                    ed25519_dalek::Keypair::generate(rng),
                    params.clone(),
                    pvss_params.clone(),
                    rng,
                )
                .unwrap(),
            );
        }
        use std::collections::VecDeque;
        let mut messages = VecDeque::new();

        use itertools::Itertools;
        let mut stake = (1..151u64)
            .map(|i| if i < 10 { 1000 } else { 1 })
            .collect::<Vec<_>>();

        for (participant, stake) in contexts.iter_mut().zip_eq(stake.iter()) {
            let announce = participant.announce(*stake);
            messages.push_back(announce);
        }

        let msg_loop =
            |contexts: &mut Vec<PubliclyVerifiableDKG<E>>,
             messages: &mut VecDeque<SignedMessage>| loop {
                if messages.is_empty() {
                    break;
                }
                let signed_message = messages.pop_front().unwrap();
                for node in contexts.iter_mut() {
                    let (_, message) = signed_message.verify().unwrap();
                    let new_msg = node
                        .handle_message(&signed_message.signer, message)
                        .unwrap();
                    if let Some(new_msg) = new_msg {
                        messages.push_back(new_msg);
                    }
                }
            };

        msg_loop(&mut contexts, &mut messages);

        for participant in contexts.iter_mut() {
            participant.finish_announce().unwrap();
        }

        msg_loop(&mut contexts, &mut messages);

        let mut dealt_weight = 0u32;
        for participant in contexts.iter_mut() {
            if dealt_weight < params.total_weight - params.security_threshold {
                let msg = participant.share(rng).unwrap();
                messages.push_back(msg);
                dealt_weight += participant.participants[participant.me].weight;
                dbg!(participant.participants[participant.me].weight);
            }
        }
        msg_loop(&mut contexts, &mut messages);

        contexts[0].final_key();
    }
}

#[test]
fn test_serialize() {
    use ark_ec::{AffineCurve, ProjectiveCurve};
    let rng = &mut ark_std::test_rng();
    type G1 = ark_bls12_381::G1Affine;
    type G2 = ark_bls12_381::G2Affine;

    let key = ed25519_dalek::Keypair::generate(rng);

    let num_shares = 8192 / 150;
    let coeffs = (0..(8192 / 3))
        .map(|i| G1::prime_subgroup_generator())
        .collect::<Vec<_>>();
    let shares = (0..150)
        .map(|i| {
            (0..num_shares)
                .map(|j| G2::prime_subgroup_generator())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let pvss = PubliclyVerifiableSS::<ark_bls12_381::Bls12_381> {
        coeffs,
        u_hat_2: G2::prime_subgroup_generator(),
        shares,
        sigma: (
            G2::prime_subgroup_generator(),
            G2::prime_subgroup_generator(),
        ),
    };
    let msg =
        SignedMessage::sign(0, &PubliclyVerifiableMessage::Sharing(pvss), &key);
}

#[test]
fn test_deserialize() {
    use ark_ec::{AffineCurve, ProjectiveCurve};
    let rng = &mut ark_std::test_rng();
    type G1 = ark_bls12_381::G1Affine;
    type G2 = ark_bls12_381::G2Affine;

    let key = ed25519_dalek::Keypair::generate(rng);

    let num_shares = 8192 / 150;
    let coeffs = (0..(8192 / 3))
        .map(|i| G1::prime_subgroup_generator())
        .collect::<Vec<_>>();
    let shares = (0..150)
        .map(|i| {
            (0..num_shares)
                .map(|j| G2::prime_subgroup_generator())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let pvss = PubliclyVerifiableSS::<ark_bls12_381::Bls12_381> {
        coeffs,
        u_hat_2: G2::prime_subgroup_generator(),
        shares,
        sigma: (
            G2::prime_subgroup_generator(),
            G2::prime_subgroup_generator(),
        ),
    };
    let msg =
        SignedMessage::sign(0, &PubliclyVerifiableMessage::Sharing(pvss), &key);
    let msg: PubliclyVerifiableMessage<ark_bls12_381::Bls12_381> =
        msg.verify().unwrap().1;
}
