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

// DKG parameters
#[derive(Copy, Clone, Debug)]
pub struct Params {
    pub failure_threshold: u32,  // failure threshold
    pub security_threshold: u32, // threshold
    pub total_weight: u32,       // total weight
}

#[derive(Debug)]
pub struct ParticipantBuilder {
    pub ed_key: ed25519::PublicKey,
    pub dh_key: dh::AsymmetricPublicKey,
    pub stake: f64,
}

#[derive(Clone, Debug)]
pub struct Participant {
    pub ed_key: ed25519::PublicKey,
    pub dh_key: dh::AsymmetricPublicKey,
    pub weight: u32,
    pub share_range: std::ops::Range<usize>,
    pub share_domain: Vec<Scalar>,
    pub a_i: fastpoly::SubproductTree, // subproduct tree of polynomial with zeros at share_domain
    pub a_i_prime: DensePolynomial<Scalar>, // derivative of a_i
}

#[derive(Debug)]
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
    //pub ck: Rc<Powers<Curve>>,
    //pub vk: Rc<VerifierKey<Curve>>,
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
    ) -> Context {
        let domain = ark_poly::Radix2EvaluationDomain::<Scalar>::new(
            params.total_weight as usize,
        )
        .unwrap();

        Context {
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
        }
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
    ) -> Option<SignedMessage> {
        let mut initial_phase_weight = 0u32;
        for (i, p) in self.participants.iter().enumerate() {
            initial_phase_weight += p.weight;
            if initial_phase_weight
                >= self.params.total_weight - self.params.security_threshold
            {
                if i >= self.me {
                    return Some(self.deal(rng));
                } else {
                    return None;
                }
            }
        }
        None
    }

    pub fn deal<R: rand::Rng + rand::CryptoRng + Sized>(
        &mut self,
        rng: &mut R,
    ) -> SignedMessage {
        use ark_std::UniformRand;

        let vss = crate::syncvss::sh::Context::new_send(
            &Scalar::rand(rng),
            &self,
            rng,
        );

        let encrypted_shares = vss.encrypted_shares.clone();
        self.vss.insert(self.me as u32, vss);

        SignedMessage::new(
            &Message {
                tau: self.tau,
                payload: MessagePayload::EncryptedShares(encrypted_shares),
            },
            &self.ed_key,
        )
    }
    pub fn partition_domain(&mut self) {
        use ark_ff::{Field, One};
        if let State::Init { participants } = &mut self.state {
            // Sort participants from greatest to least stake
            participants.sort_by(|a, b| b.stake.partial_cmp(&a.stake).unwrap());
        }
        //TODO: the borrow checker demands this immutable borrow
        if let State::Init { participants } = &self.state {
            // Compute the total amount staked
            let total_stake: f64 =
                participants.iter().map(|p| p.stake).sum::<f64>().into();

            // Compute the weight of each participant rounded down
            let mut weights: Vec<u32> = participants
                .iter()
                .map(|p| {
                    ((self.params.total_weight as f64) * p.stake / total_stake)
                        .floor() as u32
                })
                .collect();

            // Add any excess weight to the largest weight participants
            let adjust_weight = self
                .params
                .total_weight
                .checked_sub(weights.iter().sum())
                .unwrap() as usize;
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
                let a_i = fastpoly::subproduct_tree(&share_domain);
                let a_i_prime = fastpoly::derivative(&a_i.M);
                self.participants.push(Participant {
                    ed_key: participant.ed_key,
                    dh_key: participant.dh_key,
                    weight,
                    share_range,
                    share_domain,
                    a_i,
                    a_i_prime,
                });
                allocated_weight =
                    allocated_weight.checked_add(weight as usize).unwrap();
            }
            self.me = self
                .participants
                .iter()
                .position(|p| p.ed_key == self.ed_key.public)
                .unwrap(); //TODO: can unwrap fail?
                           /*self.participants
                           .get_mut(self.me)
                           .unwrap()
                           .init_share_domain(&self.domain);*/
        }
    }
    pub fn finish_announce(&mut self) {
        self.partition_domain();
        self.state = State::Sharing {
            finalized_weight: 0u32,
        };
    }

    pub fn handle_message(
        &mut self,
        msg: &crate::msg::SignedMessage,
    ) -> Result<Option<SignedMessage>, anyhow::Error> {
        use crate::msg::MessagePayload;
        let signer = msg.signer;
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
                        ed_key: signer,
                        dh_key,
                        stake: stake as f64,
                    });
                }
                Ok(None)
            }
            MessagePayload::EncryptedShares(encrypted_shares) => {
                if signer == self.ed_key.public {
                    //
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
                    let dealer = self
                        .participants
                        .iter()
                        .position(|p| p.ed_key == signer)
                        .unwrap() as u32; //TODO: unwrap can fail; also this is not a good workaround for finding dealer from ed_key
                    if self.vss.contains_key(&dealer) {
                        return Err(anyhow!("Repeat dealer {}", dealer));
                    }
                    let mut vss = crate::syncvss::sh::Context::new_recv(
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
                            .find(|p| p.ed_key == signer)
                            .unwrap()
                            .weight; //TODO: unwrap can fail; also this is not a good workaround for finding signer from ed_key

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
                    let dealer = self
                        .participants
                        .iter()
                        .position(|p| p.ed_key == signer)
                        .unwrap() as u32; //TODO: unwrap can fail; also this is not a good workaround for finding dealer from ed_key

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
    //let (ck, vk) = crate::fastkzg::trim(&pp, params.total_weight);
    let (powers_of_h, powers_of_g) =
        (Rc::new(powers_of_h), Rc::new(pp.powers_of_g));
    for _ in 0..10 {
        let mut contexts = vec![];
        for _ in 0..10 {
            contexts.push(Context::new(
                0u32, //tau
                ed25519::Keypair::generate(rng),
                &params,
                powers_of_g.clone(),
                powers_of_h.clone(),
                pp.beta_h,
                rng,
            ));
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
            participant.finish_announce();
        }

        msg_loop(&mut contexts, &mut messages);

        for participant in contexts.iter_mut() {
            let msg = participant.deal_if_turn(rng);
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
