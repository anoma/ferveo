#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]
#![allow(unused_imports)]

use ark_bls12_381::{Fr, G1Affine, G2Affine};
use ark_poly_commit::kzg10::{Powers, VerifierKey};
use num::integer::div_ceil;
use rand::Rng;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;

use crate::fastpoly;
use crate::msg::{Message, MessagePayload, SignedMessage};
use crate::syncvss;
use crate::syncvss::dh;
use crate::{Curve, Scalar};
use anyhow::anyhow;
use ark_poly::{
    polynomial::univariate::DensePolynomial, polynomial::UVPolynomial,
    EvaluationDomain, Polynomial,
};
use ed25519_dalek as ed25519;

#[cfg(feature = "borsh")]
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
#[cfg(feature = "borsh")]
use borsh::maybestd::io as borsh_io;
#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

// DKG parameters
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct Params {
    pub failure_threshold: u32,  // failure threshold
    pub security_threshold: u32, // threshold
    pub total_weight: u32,       // total weight
}

#[derive(Debug)]
pub struct ParticipantBuilder {
    pub ed_key: ed25519::PublicKey,
    pub dh_key: dh::AsymmetricPublicKey,
    pub stake: u64,
}

#[derive(Clone, Debug)]
pub struct Participant {
    pub ed_key: ed25519::PublicKey,
    pub dh_key: dh::AsymmetricPublicKey,
    pub weight: u32,
    pub share_range: std::ops::Range<usize>,
    pub share_domain: fastpoly::SubproductDomain, // subproduct tree of polynomial with zeros at share_domain
    pub domain_commitment: Option<G2Affine>, //Commitment to subproduct domain}
}
#[derive(Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub enum State {
    Init {
        participants: Vec<ParticipantBuilder>,
    },
    Sharing {
        finalized_weight: u32,
    },
    Success,
    Failure,
}

pub struct Context {
    pub tau: u32,
    pub dh_key: dh::AsymmetricKeypair,
    pub ed_key: ed25519::Keypair,
    pub params: Params,
    pub participants: Vec<Participant>,
    pub vss: BTreeMap<u32, syncvss::sh::Context>,
    pub domain: ark_poly::Radix2EvaluationDomain<Scalar>,
    pub state: State,
    pub me: usize,
    pub powers_of_g: Rc<Vec<G1Affine>>,
    pub powers_of_h: Rc<Vec<G2Affine>>,
    pub beta_h: G2Affine,
}

impl Context {
    pub fn new<R: rand::Rng + rand::CryptoRng + Sized>(
        tau: u32,
        ed_key: ed25519::Keypair,
        params: &Params,
        powers_of_g: Rc<Vec<G1Affine>>,
        powers_of_h: Rc<Vec<G2Affine>>,
        beta_h: G2Affine,
        rng: &mut R,
    ) -> Result<Context, anyhow::Error> {
        let domain = ark_poly::Radix2EvaluationDomain::<Scalar>::new(
            params.total_weight as usize,
        )
        .ok_or_else(|| anyhow::anyhow!("unable to construct domain"))?;

        Ok(Context {
            tau,
            dh_key: dh::AsymmetricKeypair::new(rng),
            ed_key,
            params: *params,
            participants: vec![],
            vss: BTreeMap::new(),
            domain,
            state: State::Init {
                participants: vec![],
            },
            me: 0, // TODO: invalid value
            powers_of_g,
            powers_of_h,
            beta_h,
        })
    }
    pub fn final_key(&self) -> G1Affine {
        use crate::syncvss::sh::State as VSSState;
        use ark_ff::Zero;
        self.vss
            .iter()
            .filter_map(|(_, vss)| {
                if let VSSState::Success { final_secret } = vss.state {
                    Some(final_secret)
                } else {
                    None
                }
            })
            // .sum() //TODO: it would be nice to use Sum trait here, but not implemented for G1Affine
            .fold(G1Affine::zero(), |i, j| i + j)
    }

    pub fn announce(&mut self, stake: u64) -> SignedMessage {
        SignedMessage::new(
            &Message {
                tau: self.tau,
                payload: MessagePayload::Announce {
                    stake,
                    dh_key: self.dh_key.public(),
                },
            },
            &self.ed_key,
        )
    }
    pub fn deal_if_turn<R: rand::Rng + rand::CryptoRng + Sized>(
        &mut self,
        rng: &mut R,
    ) -> Result<Option<SignedMessage>, anyhow::Error> {
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

    pub fn deal<R: rand::Rng + rand::CryptoRng + Sized>(
        &mut self,
        rng: &mut R,
    ) -> Result<SignedMessage, anyhow::Error> {
        use ark_std::UniformRand;

        let vss = crate::syncvss::sh::Context::new_send(
            &Scalar::rand(rng),
            &self,
            rng,
        )?;

        let encrypted_shares = vss.encrypted_shares.clone();
        self.vss.insert(self.me as u32, vss);

        Ok(SignedMessage::new(
            &Message {
                tau: self.tau,
                payload: MessagePayload::EncryptedShares(encrypted_shares),
            },
            &self.ed_key,
        ))
    }
    pub fn partition_domain(&mut self) -> Result<(), anyhow::Error> {
        use ark_ff::{Field, One};
        if let State::Init { participants } = &mut self.state {
            // Sort participants from greatest to least stake
            participants.sort_by(|a, b| b.stake.cmp(&a.stake));
        }
        //TODO: the borrow checker demands this immutable borrow
        if let State::Init { participants } = &self.state {
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
                .ok_or_else(|| anyhow::anyhow!("adjusted weight negative"))?
                as usize;
            for i in &mut weights[0..adjust_weight] {
                *i += 1;
            }

            // total_weight is allocated among all participants
            assert_eq!(weights.iter().sum::<u32>(), self.params.total_weight);

            let mut allocated_weight = 0usize;
            let mut domain_element = Fr::one();
            for (participant, weight) in participants.iter().zip(weights) {
                let share_range =
                    allocated_weight..allocated_weight + weight as usize;
                let mut share_domain = Vec::with_capacity(weight as usize);
                for _ in 0..weight {
                    share_domain.push(domain_element);
                    domain_element *= self.domain.group_gen;
                }
                //let share_domain = share_domain.into_boxed_slice();
                let share_domain =
                    fastpoly::SubproductDomain::new(share_domain);
                //let a_i_prime = fastpoly::derivative(&a_i.m);
                self.participants.push(Participant {
                    ed_key: participant.ed_key,
                    dh_key: participant.dh_key,
                    weight,
                    share_range,
                    share_domain,
                    domain_commitment: None,
                });
                allocated_weight =
                    allocated_weight.checked_add(weight as usize).ok_or_else(
                        || anyhow::anyhow!("allocated weight overflow"),
                    )?;
            }
            self.me = self
                .find_by_key(&self.ed_key.public)
                .ok_or_else(|| anyhow::anyhow!("self not found"))?;
            self.participants[self.me].domain_commitment =
                Some(crate::fastkzg::g2_commit(
                    &self.powers_of_h,
                    &self.participants[self.me].share_domain.t.m,
                )?);
        }
        Ok(())
    }
    pub fn finish_announce(&mut self) -> Result<(), anyhow::Error> {
        self.partition_domain()?;
        self.state = State::Sharing {
            finalized_weight: 0u32,
        };
        Ok(())
    }
    //TODO: this is not a good workaround for finding dealer from ed_key
    pub fn find_by_key(&self, ed_key: &ed25519::PublicKey) -> Option<usize> {
        self.participants.iter().position(|p| p.ed_key == *ed_key)
    }

    pub fn handle_message(
        &mut self,
        msg: &crate::msg::SignedMessage,
    ) -> Result<Option<SignedMessage>, anyhow::Error> {
        use crate::msg::MessagePayload;
        let signer = &msg.signer;
        let msg = msg.verify()?;

        if msg.tau != self.tau {
            return Err(anyhow!(
                "wrong tau={}, expected tau={}",
                msg.tau,
                self.tau
            ));
        }
        match msg.payload {
            MessagePayload::Announce { stake, dh_key } => {
                if let State::Init { participants } = &mut self.state {
                    participants.push(ParticipantBuilder {
                        ed_key: *signer,
                        dh_key,
                        stake,
                    });
                }
                Ok(None)
            }
            MessagePayload::EncryptedShares(encrypted_shares) => {
                if *signer == self.ed_key.public {
                    return Ok(Some(SignedMessage::new(
                        &Message {
                            tau: self.tau,
                            payload: MessagePayload::Ready(
                                crate::syncvss::sh::ReadyMsg {
                                    dealer: self.me as u32,
                                    commitment: self.vss[&(self.me as u32)]
                                        .encrypted_shares
                                        .commitment,
                                },
                            ),
                        },
                        &self.ed_key,
                    )));
                }
                if let State::Sharing { finalized_weight } = self.state {
                    let dealer = self.find_by_key(signer).ok_or_else(|| {
                        anyhow::anyhow!("received dealing from unknown dealer")
                    })? as u32;
                    if self.vss.contains_key(&dealer) {
                        return Err(anyhow!("Repeat dealer {}", dealer));
                    }
                    let vss = crate::syncvss::sh::Context::new_recv(
                        dealer,
                        &encrypted_shares,
                        self,
                    )?;
                    let commitment = vss.encrypted_shares.commitment.clone();
                    self.vss.insert(dealer, vss);
                    return Ok(Some(SignedMessage::new(
                        &Message {
                            tau: self.tau,
                            payload: MessagePayload::Ready(
                                crate::syncvss::sh::ReadyMsg {
                                    dealer,
                                    commitment,
                                },
                            ),
                        },
                        &self.ed_key,
                    )));
                }
                Ok(None)
            }
            MessagePayload::Ready(ready) => {
                if let State::Sharing { finalized_weight } = self.state {
                    if let Some(vss) = self.vss.get_mut(&ready.dealer) {
                        let signer_weight = self
                            .participants
                            .iter()
                            .find(|p| p.ed_key == *signer)
                            .ok_or_else(|| {
                                anyhow::anyhow!(
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
                                return Ok(Some(SignedMessage::new(
                                    &Message {
                                        tau: self.tau,
                                        payload: MessagePayload::Finalize(
                                            finalize,
                                        ),
                                    },
                                    &self.ed_key,
                                )));
                            }
                        }
                    }
                }
                Ok(None)
            }
            MessagePayload::Finalize(finalize) => {
                if let State::Sharing { finalized_weight } = self.state {
                    let dealer = self.find_by_key(signer).ok_or_else(|| {
                        anyhow::anyhow!("received finalize from unknown dealer")
                    })? as u32; //TODO: this is not a good workaround for finding dealer from ed_key

                    if let Some(context) = self.vss.get_mut(&dealer) {
                        let minimum_ready_weight = self.params.total_weight
                            //- self.params.failure_threshold
                            - self.params.security_threshold;
                        context.handle_finalize(
                            &finalize,
                            minimum_ready_weight,
                            &self.powers_of_g[0],
                        )?;
                        // Finalize succeeded
                        let finalized_weight = finalized_weight
                            + self.participants[dealer as usize].weight;
                        if finalized_weight >= minimum_ready_weight {
                            self.state = State::Success;
                        } else {
                            self.state = State::Sharing { finalized_weight };
                        }
                    }
                }
                Ok(None)
            }
            MessagePayload::Dispute(dispute) => {
                use crate::syncvss::dispute;
                match dispute::handle_dispute(self, &dispute) {
                    // TODO: Do something important with dispute result
                    dispute::DisputeResolution::DealerFault => Ok(None),
                    dispute::DisputeResolution::ComplainerFault => Ok(None),
                }
            }
        }
    }
}

#[test]
fn dkg() {
    let rng = &mut ark_std::test_rng();
    use syncvss::dh;

    let params = Params {
        failure_threshold: 1,
        security_threshold: 33,
        total_weight: 100,
    };

    let (pp, powers_of_h) =
        crate::fastkzg::setup(params.total_weight as usize, rng).unwrap();
    let (powers_of_h, powers_of_g) =
        (Rc::new(powers_of_h), Rc::new(pp.powers_of_g));
    for _ in 0..10 {
        let mut contexts = vec![];
        for _ in 0..10 {
            contexts.push(
                Context::new(
                    0u32, //tau
                    ed25519::Keypair::generate(rng),
                    &params,
                    powers_of_g.clone(),
                    powers_of_h.clone(),
                    pp.beta_h,
                    rng,
                )
                .unwrap(),
            );
        }
        use std::collections::VecDeque;
        let mut messages = VecDeque::new();

        let stake = vec![
            10u64, 20u64, 30u64, 40u64, 50u64, 60u64, 70u64, 80u64, 90u64,
            100u64,
        ];
        for (participant, stake) in contexts.iter_mut().zip(stake.iter()) {
            let announce = participant.announce(*stake);
            messages.push_back(announce);
        }

        let msg_loop =
            |contexts: &mut Vec<Context>,
             messages: &mut VecDeque<SignedMessage>| loop {
                if messages.is_empty() {
                    break;
                }
                let message = messages.pop_front().unwrap();
                for node in contexts.iter_mut() {
                    let new_msg = node.handle_message(&message).unwrap();
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

        for participant in contexts.iter_mut() {
            let msg = participant.deal_if_turn(rng).unwrap();
            if let Some(msg) = msg {
                messages.push_back(msg);
            }
        }

        use ark_ff::Zero;
        let mut final_secret = G1Affine::zero();
        for c in contexts.iter() {
            for v in c.vss.values() {
                if let Some(finalize_msg) = v.finalize_msg {
                    final_secret = final_secret + finalize_msg.rebased_secret;
                }
            }
        }
        let final_secret: G1Affine = final_secret.into();

        msg_loop(&mut contexts, &mut messages);

        for participant in contexts.iter() {
            assert!(matches!(participant.state, State::Success));
        }
        let final_keys = contexts
            .iter()
            .map(|c| c.final_key())
            .collect::<Vec<G1Affine>>();

        assert!(final_keys.iter().all(|&key| key == final_secret));
    }
}

#[cfg(feature = "borsh")]
fn ark_to_bytes<T: CanonicalSerialize>(value: T) -> Vec<u8> {
    let mut bytes = vec![0u8; value.serialized_size()];
    value.serialize(&mut bytes).expect("failed to serialize");
    bytes
}

#[cfg(feature = "borsh")]
fn ark_from_bytes<T: CanonicalDeserialize>(bytes: &[u8]) -> Option<T> {
    CanonicalDeserialize::deserialize(bytes).ok()
}

#[cfg(feature = "borsh")]
impl BorshSerialize for ParticipantBuilder {
    fn serialize<W: borsh_io::Write>(
        &self,
        writer: &mut W,
    ) -> borsh_io::Result<()> {
        let ed_key = self.ed_key.to_bytes();
        BorshSerialize::serialize(&(&ed_key, &self.dh_key, &self.stake), writer)
    }
}

#[cfg(feature = "borsh")]
impl BorshDeserialize for ParticipantBuilder {
    fn deserialize(buf: &mut &[u8]) -> borsh_io::Result<Self> {
        let (ed_key, dh_key, stake): (Vec<u8>, dh::AsymmetricPublicKey, u64) =
            BorshDeserialize::deserialize(buf)?;
        let ed_key = ed25519::PublicKey::from_bytes(&ed_key)
            .expect("failed to deserialize");
        Ok(Self {
            ed_key,
            dh_key,
            stake,
        })
    }
}

#[cfg(feature = "borsh")]
impl BorshSerialize for Participant {
    fn serialize<W: borsh_io::Write>(
        &self,
        writer: &mut W,
    ) -> borsh_io::Result<()> {
        let ed_key = self.ed_key.to_bytes();
        let share_range =
            (self.share_range.start as u64, self.share_range.end as u64);
        let domain_commitment: Option<Vec<u8>> =
            self.domain_commitment.map(ark_to_bytes);
        BorshSerialize::serialize(
            &(
                &ed_key,
                &self.dh_key,
                &self.weight,
                &share_range,
                &self.share_domain,
                &domain_commitment,
            ),
            writer,
        )
    }
}

#[cfg(feature = "borsh")]
impl BorshDeserialize for Participant {
    fn deserialize(buf: &mut &[u8]) -> borsh_io::Result<Self> {
        let (
            ed_key,
            dh_key,
            weight,
            share_range,
            share_domain,
            domain_commitment,
        ): (
            Vec<u8>,
            dh::AsymmetricPublicKey,
            u32,
            (u64, u64),
            fastpoly::SubproductDomain,
            Option<Vec<u8>>,
        ) = BorshDeserialize::deserialize(buf)?;
        let ed_key = ed25519::PublicKey::from_bytes(&ed_key)
            .expect("failed to deserialize");
        let share_range = std::ops::Range {
            start: share_range.0 as usize,
            end: share_range.1 as usize,
        };
        let domain_commitment = domain_commitment.map(|bytes| {
            ark_from_bytes(&bytes).expect("failed to deserialize")
        });
        Ok(Self {
            ed_key,
            dh_key,
            weight,
            share_range,
            share_domain,
            domain_commitment,
        })
    }
}

#[cfg(feature = "borsh")]
impl BorshSerialize for Context {
    fn serialize<W: borsh_io::Write>(
        &self,
        writer: &mut W,
    ) -> borsh_io::Result<()> {
        let ed_key = self.ed_key.to_bytes();
        let domain = ark_to_bytes(self.domain);
        let powers_of_g: Vec<_> =
            self.powers_of_g.iter().cloned().map(ark_to_bytes).collect();
        let powers_of_h: Vec<_> =
            self.powers_of_h.iter().cloned().map(ark_to_bytes).collect();
        let beta_h = ark_to_bytes(self.beta_h);
        BorshSerialize::serialize(
            &(
                &self.tau,
                &self.dh_key,
                &ed_key,
                &self.params,
                &self.participants,
                &self.vss,
                &domain,
                &self.state,
                &(self.me as u64),
                &powers_of_g,
                &powers_of_h,
                &beta_h,
            ),
            writer,
        )
    }
}

#[cfg(feature = "borsh")]
impl BorshDeserialize for Context {
    fn deserialize(buf: &mut &[u8]) -> borsh_io::Result<Self> {
        let (
            tau,
            dh_key,
            ed_key,
            params,
            participants,
            vss,
            domain,
            state,
            me,
            powers_of_g,
            powers_of_h,
            beta_h,
        ): (
            u32,
            dh::AsymmetricKeypair,
            Vec<u8>,
            Params,
            Vec<Participant>,
            BTreeMap<u32, syncvss::sh::Context>,
            Vec<u8>,
            State,
            u64,
            Vec<Vec<u8>>,
            Vec<Vec<u8>>,
            Vec<u8>,
        ) = BorshDeserialize::deserialize(buf)?;
        let ed_key = ed25519::Keypair::from_bytes(&ed_key)
            .expect("failed to deserialize");
        let domain = ark_from_bytes(&domain).expect("failed to deserialize");
        let powers_of_g: Vec<_> = powers_of_g
            .iter()
            .map(|bytes| ark_from_bytes(&bytes).expect("failed to deserialize"))
            .collect();
        let powers_of_h: Vec<_> = powers_of_h
            .iter()
            .map(|bytes| ark_from_bytes(&bytes).expect("failed to deserialize"))
            .collect();
        let beta_h = ark_from_bytes(&beta_h).expect("failed to deserialize");
        Ok(Self {
            tau,
            dh_key,
            ed_key,
            params,
            participants,
            vss,
            domain,
            state,
            me: me as usize,
            powers_of_g: Rc::new(powers_of_g),
            powers_of_h: Rc::new(powers_of_h),
            beta_h,
        })
    }
}
