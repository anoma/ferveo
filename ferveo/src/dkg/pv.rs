use crate::*;
use ark_ec::bn::TwistType::D;
use ark_ec::PairingEngine;
use ark_ff::Field;
use ark_std::{end_timer, start_timer};
use ferveo_common::{PublicKey, ValidatorPublicKey};
use std::collections::BTreeMap;

/// The DKG context that holds all of the local state for participating in the DKG
#[derive(Debug)]
pub struct PubliclyVerifiableDkg<E: PairingEngine> {
    pub params: Params,
    pub pvss_params: PubliclyVerifiableParams<E>,
    pub session_keypair: ferveo_common::Keypair<E>,
    pub validators: Vec<ferveo_common::Validator<E>>,
    pub vss: BTreeMap<u32, PubliclyVerifiableSS<E>>,
    pub domain: ark_poly::Radix2EvaluationDomain<E::Fr>,
    pub state: DkgState<E>,
    pub me: usize,
    pub validator_set: ValidatorSet,
}

#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
/// Represents a tendermint validator
pub struct TendermintValidator {
    /// Total voting power in tendermint consensus
    pub power: u64,
    /// The established address of the validator
    pub address: String,
}

#[derive(Clone, Debug)]
/// The set of tendermint validators for a dkg instance
pub struct ValidatorSet {
    pub validators: Vec<TendermintValidator>,
}

impl ValidatorSet {
    /// Sorts the validators from highest to lowest. This ordering
    /// first considers staking weight and breaks ties on established
    /// address
    pub fn new(mut validators: Vec<TendermintValidator>) -> Self {
        // reverse the ordering here
        validators.sort_by(|a, b| b.cmp(a));
        Self { validators }
    }

    /// Get the total voting power of the validator set
    pub fn total_voting_power(&self) -> u64 {
        self.validators.iter().map(|v| v.power).sum()
    }
}

#[derive(Clone)]
/// Represents a tendermint validator
pub struct TendermintValidator {
    /// Total voting power in tendermint consensus
    pub power: u64
}

#[derive(Clone)]
/// The set of tendermint validators for a dkg instance
pub struct ValidatorSet {
    pub validators: Vec<TendermintValidator>,
}

impl ValidatorSet {
    pub fn total_voting_power(&self) -> u64 {
        self.validators
            .iter()
            .map(|v| v.power)
            .sum()
    }
}


impl<E: PairingEngine> PubliclyVerifiableDkg<E> {
    /// Create a new DKG context to participate in the DKG
    /// Every identity in the DKG is linked to an ed25519 public key;
    /// `validator_set`: The set of validators and their respective voting powers
    ///                  *IMPORTANT: this set should be reverse sorted*
    /// `params` contains the parameters of the DKG such as number of shares
    /// `rng` is a cryptographic random number generator
    pub fn new<R: Rng>(
        validator_set: ValidatorSet,
        params: Params,
        me: TendermintValidator,
        rng: &mut R,
    ) -> Result<Self> {
        use ark_std::UniformRand;
        let domain = ark_poly::Radix2EvaluationDomain::<E::Fr>::new(
            params.total_weight as usize,
        )
        .ok_or_else(|| anyhow!("unable to construct domain"))?;

        // keep track of the owner of this instance in the validator set
        let me = validator_set
            .validators
            .binary_search_by(|probe| me.cmp(probe))
            .map_err(|_| anyhow!("could not find this validator in the provided validator set"))?;

        // partition out weight shares of validators based on their voting power
        let mut validators = partition_domain(&params, &validator_set)?;

        // We don't need to wait for announcements to store our own ephemeral public key
        let session_keypair = ferveo_common::Keypair::<E>::new(rng);
        validators[me].key =
            ValidatorPublicKey::Announced(session_keypair.public());
        Ok(Self {
            session_keypair,
            params,
            pvss_params: PubliclyVerifiableParams::<E> {
                g: E::G1Projective::prime_subgroup_generator(),
                h: E::G2Projective::prime_subgroup_generator(),
            },
            vss: BTreeMap::new(),
            domain,
            state: DkgState::Init { announced: 1 },
            me,
            validators,
            validator_set,
        })
    }

    pub fn announce(&mut self) -> Message<E> {
        Message::Announce(self.session_keypair.public())
    }

    /// Create a new PVSS instance within this DKG session, contributing to the final key
    /// `rng` is a cryptographic random number generator
    /// Returns a PVSS dealing message to post on-chain
    pub fn share<R: Rng>(&mut self, rng: &mut R) -> Result<Message<E>> {
        use ark_std::UniformRand;
        print_time!("PVSS Sharing");
        let vss = Pvss::<E>::new(&E::Fr::rand(rng), self, rng)?;

        let sharing = vss.clone();
        self.vss.insert(self.me as u32, vss);
        match &mut self.state {
            DkgState::Shared {
                ref mut accumulated_weight,
            } => *accumulated_weight += self.validators[self.me].weight,
            DkgState::Dealt => {}
            _ => {
                return Err(anyhow!("Can only share once all validators have announced their public keys"));
            }
        }
        Ok(Message::Deal(sharing))
    }

    /// Aggregate all received PVSS messages into a single message, prepared to post on-chain
    pub fn aggregate(&self) -> Result<Message<E>> {
        match self.state {
            DkgState::Dealt | DkgState::Success { .. } => {
                Ok(Message::Aggregate(aggregate(self)))
            }
            _ => {
                Err(anyhow!("Not enough PVSS transcripts recieved to aggreate"))
            }
        }
    }

    /// Returns the public key generated by the DKG
    pub fn final_key(&self) -> E::G1Affine {
        self.vss
            .iter()
            .map(|(_, vss)| vss.coeffs[0].into_projective())
            .sum::<E::G1Projective>()
            .into_affine()
    }

    /// Verify a DKG related message in a block proposal
    /// `sender` is the validator of the sender of the message
    /// `payload` is the content of the message
    pub fn verify_message<R: Rng>(
        &self,
        sender: &TendermintValidator,
        payload: &Message<E>,
        rng: &mut R,
    ) -> Result<()> {
        match payload {
            Message::Announce(_) if matches!(self.state, DkgState::Init{..}) => {
                let sender = self.validator_set
                    .validators
                    .binary_search_by(|probe| sender.cmp(probe))
                    .map_err(|_| anyhow!("dkg received unknown validator"))?;
                if matches!(self.validators[sender].key, ValidatorPublicKey::Unannounced) {
                    Ok(())
                } else {
                    Err(anyhow!("This validator has already established a session key"))
                }
            },
            Message::Deal(pvss) if matches!(self.state, DkgState::Shared{..} | DkgState::Dealt) => {
                // TODO: If this is two slow, we can convert self.validators to
                // an address keyed hashmap after partitioning the weight shares
                // in the [`new`] method
                let sender = self.validator_set
                    .validators
                    .binary_search_by(|probe| sender.cmp(probe))
                    .map_err(|_| anyhow!("dkg received unknown dealer"))?;
                if self.vss.contains_key(&(sender as u32)) {
                    Err(anyhow!("Repeat dealer {}", sender))
                } else if !pvss.verify_optimistic() {
                    Err(anyhow!("Invalid PVSS transcript"))
                } else {
                    Ok(())
                }
            }
            Message::Aggregate(pvss) if matches!(self.state, DkgState::Dealt | DkgState::Success {..}) => {
                let minimum_weight = self.params.total_weight
                    - self.params.security_threshold;
                let verified_weight = pvss.verify_aggregation(self, rng)?;
                // we reject aggregations that fail to meet the security threshold
                if verified_weight < minimum_weight {
                    Err(
                        anyhow!("Aggregation failed because the verified weight was insufficient")
                    )
                } else {
                    Ok(())
                }
            }
            _ => Err(anyhow!("DKG state machine is not in correct state to verify this message"))
        }
    }

    /// After consensus has agreed to include a verified
    /// message on the blockchain, we apply the chains
    /// to the state machine
    pub fn apply_message(
        &mut self,
        sender: TendermintValidator,
        payload: Message<E>,
    ) -> Result<()> {
        match payload {
            Message::Announce(pk) if matches!(self.state, DkgState::Init{..}) => {
                // Add the ephemeral public key and pvss transcript
                let sender = self.validator_set
                    .validators
                    .binary_search_by(|probe| sender.cmp(probe))
                    .map_err(|_| anyhow!("dkg received unknown dealer"))?;
                self.validators[sender].key
                    = ValidatorPublicKey::Announced(pk);

                // keep track of announced validators until we know
                // everyone's session keys
                if let DkgState::Init{ref mut announced} =  &mut self.state {
                    *announced += 1;
                    if *announced == self.validators.len() as u32 {
                        self.state = DkgState::Shared {accumulated_weight: 0};
                    }
                }
                Ok(())
            }
            Message::Deal(pvss) if matches!(self.state, DkgState::Shared{..} | DkgState::Dealt) => {
                // Add the ephemeral public key and pvss transcript
                let sender = self.validator_set
                    .validators
                    .binary_search_by(|probe| sender.cmp(probe))
                    .map_err(|_| anyhow!("dkg received unknown dealer"))?;
                self.vss.insert(sender as u32, pvss);

                // we keep track of the amount of weight seen until the security
                // threshold is met. Then we may change the state of the DKG
                if let DkgState::Shared{ref mut accumulated_weight} =  &mut self.state {
                    *accumulated_weight += self.validators[sender].weight;
                    if *accumulated_weight
                        >= self.params.total_weight - self.params.security_threshold {
                      self.state = DkgState::Dealt;
                    }
                }
                Ok(())
            }
            Message::Aggregate(_) if matches!(self.state, DkgState::Dealt | DkgState::Success {..}) => {
                // change state and cache the final key
                self.state = DkgState::Success {final_key: self.final_key()};
                Ok(())
            }
            _ => Err(anyhow!("DKG state machine is not in correct state to apply this message"))
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "")]
pub enum Message<E: PairingEngine> {
    #[serde(with = "ferveo_common::ark_serde")]
    Announce(PublicKey<E>),
    #[serde(with = "ferveo_common::ark_serde")]
    Deal(Pvss<E>),
    #[serde(with = "ferveo_common::ark_serde")]
    Aggregate(AggregatedPvss<E>),
}

/// Factory functions for testing
#[cfg(test)]
mod test_common {
    pub use super::*;
    pub use ark_bls12_381::Bls12_381 as EllipticCurve;
    pub use ark_ff::UniformRand;
    pub type G1 = <EllipticCurve as PairingEngine>::G1Affine;

    /// Generate a few validators
    pub fn gen_validators() -> ValidatorSet {
        ValidatorSet::new(
            (0..4)
                .map(|i| TendermintValidator {
                    power: i,
                    address: format!("validator_{}", i),
                })
                .collect(),
        )
    }

    /// Create a test dkg
    ///
    /// The [`test_init`] module checks correctness of this setup
    pub fn setup_dkg(validator: usize) -> PubliclyVerifiableDkg<EllipticCurve> {
        let rng = &mut ark_std::test_rng();
        let validators = gen_validators();
        let me = validators.validators[validator].clone();
        PubliclyVerifiableDkg::new(
            validators,
            Params {
                tau: 0,
                security_threshold: 2,
                total_weight: 6,
            },
            me,
            rng,
        )
        .expect("Setup failed")
    }

    /// Setup a dkg instance with all announcements received
    ///
    /// The [`test_announcements`] module checks the correctness
    /// of this setup.
    pub fn setup_shared_dkg(
        validator: usize,
    ) -> PubliclyVerifiableDkg<EllipticCurve> {
        let rng = &mut ark_std::test_rng();
        let mut dkg = setup_dkg(validator);

        // generated the announcements for all other validators
        for i in 0..4 {
            if i == validator {
                continue;
            }
            let announce = Message::Announce(
                ferveo_common::Keypair::<EllipticCurve>::new(rng).public(),
            );
            let sender = dkg.validator_set.validators[i].clone();
            dkg.apply_message(sender, announce).expect("Setup failed");
        }
        dkg
    }

    /// Set up a dkg with enough pvss transcripts to meet the threshold
    ///
    /// The correctness of this function is tested in the module [`test_dealing`]
    pub fn setup_dealt_dkg() -> PubliclyVerifiableDkg<EllipticCurve> {
        let rng = &mut ark_std::test_rng();
        // gather everyone's transcripts
        let mut transcripts = vec![];
        for i in 0..4 {
            let mut dkg = setup_shared_dkg(i);
            transcripts.push(dkg.share(rng).expect("Test failed"));
        }
        // our test dkg
        let mut dkg = setup_shared_dkg(0);
        // iterate over transcripts from lowest weight to highest
        for (sender, pvss) in transcripts.into_iter().rev().enumerate() {
            dkg.apply_message(
                dkg.validator_set.validators[3 - sender].clone(),
                pvss,
            )
            .expect("Setup failed");
        }
        dkg
    }
}

/// Test initializing DKG
#[cfg(test)]
mod test_dkg_init {
    use super::test_common::*;

    /// Test that validators are correctly sorted
    #[test]
    fn test_validator_set() {
        let validators = vec![
            TendermintValidator {
                power: 0,
                address: "validator_0".into(),
            },
            TendermintValidator {
                power: 2,
                address: "validator_1".into(),
            },
            TendermintValidator {
                power: 2,
                address: "validator_2".into(),
            },
            TendermintValidator {
                power: 1,
                address: "validator_3".into(),
            },
        ];
        let expected = vec![
            validators[2].clone(),
            validators[1].clone(),
            validators[3].clone(),
            validators[0].clone(),
        ];
        let validator_set = ValidatorSet::new(validators);
        assert_eq!(validator_set.validators, expected);
    }

    /// Test that dkg fails to start if the `me` input
    /// is not in the validator set
    #[test]
    fn test_dkg_fail_unknown_validator() {
        let rng = &mut ark_std::test_rng();
        let err = PubliclyVerifiableDkg::<EllipticCurve>::new(
            gen_validators(),
            Params {
                tau: 0,
                security_threshold: 4,
                total_weight: 6,
            },
            TendermintValidator {
                power: 9001,
                address: "Goku".into(),
            },
            rng,
        )
        .expect_err("Test failed");
        assert_eq!(
            err.to_string(),
            "could not find this validator in the provided validator set"
        )
    }
}

/// Test the announcements phase of the DKG
#[cfg(test)]
mod test_announcements {
    use super::test_common::*;
    use ark_bls12_381::Bls12_381 as EllipticCurve;
    use ark_ff::UniformRand;

    /// Test that announcements are verified and
    /// applied correctly
    #[test]
    fn test_announcements() {
        let rng = &mut ark_std::test_rng();
        let mut dkg = setup_dkg(0);
        // check the initial state is correct
        assert!(matches!(dkg.state, DkgState::Init { announced: 1 }));
        assert!(matches!(
            dkg.validators[dkg.me].key,
            ValidatorPublicKey::Announced(_)
        ));

        // generated the announcements for all other validators
        for i in 1..4 {
            let announce = Message::Announce(
                ferveo_common::Keypair::<EllipticCurve>::new(rng).public(),
            );
            let sender = dkg.validator_set.validators[i].clone();
            // message should pass verification
            assert!(dkg.verify_message(&sender, &announce, rng,).is_ok());
            // message should be applied successfully
            assert!(dkg.apply_message(sender, announce).is_ok());
            // the announced key should be stored
            assert!(matches!(
                dkg.validators[i].key,
                ValidatorPublicKey::Announced(_)
            ));
            if i < 3 {
                // the announced counter should be incremented
                match dkg.state {
                    DkgState::Init { announced } => {
                        assert_eq!(announced as usize, i + 1)
                    }
                    _ => panic!("Test failed"),
                }
            } else {
                // once everyone has announced, state should be updated to shared
                assert!(matches!(
                    dkg.state,
                    DkgState::Shared {
                        accumulated_weight: 0
                    }
                ))
            }
        }
    }

    /// Test that if an announcement comes from
    /// an unknown validator, it is neither
    /// verified nor applied
    #[test]
    fn test_announce_unknown_validator() {
        let rng = &mut ark_std::test_rng();
        let mut dkg = setup_dkg(0);
        // check the initial state is correct
        assert!(matches!(dkg.state, DkgState::Init { announced: 1 }));
        for i in 0..4 {
            if i == dkg.me {
                assert!(matches!(
                    dkg.validators[i].key,
                    ValidatorPublicKey::Announced(_)
                ));
            } else {
                assert!(matches!(
                    dkg.validators[i].key,
                    ValidatorPublicKey::Unannounced
                ));
            }
        }

        let announce = Message::Announce(
            ferveo_common::Keypair::<EllipticCurve>::new(rng).public(),
        );
        let sender = TendermintValidator {
            power: 9001,
            address: "Goku".into(),
        };
        // check that verification fails
        assert!(dkg.verify_message(&sender, &announce, rng).is_err());
        // check that application fails
        assert!(dkg.apply_message(sender, announce).is_err());
        // check that state is unchanged
        assert!(matches!(dkg.state, DkgState::Init { announced: 1 }));
        for i in 0..4 {
            if i == dkg.me {
                assert!(matches!(
                    dkg.validators[i].key,
                    ValidatorPublicKey::Announced(_)
                ));
            } else {
                assert!(matches!(
                    dkg.validators[i].key,
                    ValidatorPublicKey::Unannounced
                ));
            }
        }
    }

    /// Test that an announcement from a validator fails
    /// verification if they have announced already
    #[test]
    fn test_announce_twice_fails() {
        let rng = &mut ark_std::test_rng();
        let mut dkg = setup_dkg(0);

        let announce = Message::Announce(
            ferveo_common::Keypair::<EllipticCurve>::new(rng).public(),
        );
        let sender = dkg.validator_set.validators[1].clone();
        // message should pass verification
        assert!(dkg.verify_message(&sender, &announce, rng).is_ok());
        // message should pass application
        assert!(dkg.apply_message(sender.clone(), announce.clone()).is_ok());
        // announcing a second time should fail verification
        assert!(dkg.verify_message(&sender, &announce, rng).is_err());
    }

    /// Test that announce messages are only accepted
    /// if the dkg is in [`DkgState::Init`] state
    #[test]
    fn test_announce_state_guards() {
        let rng = &mut ark_std::test_rng();
        let mut dkg = setup_dkg(0);
        // create announcement and sender
        let announce = Message::Announce(
            ferveo_common::Keypair::<EllipticCurve>::new(rng).public(),
        );
        let sender = dkg.validator_set.validators[1].clone();
        // check all non-valid states
        for state in vec![
            DkgState::Shared {
                accumulated_weight: 0,
            },
            DkgState::Dealt,
            DkgState::Success {
                final_key: G1::zero(),
            },
        ] {
            dkg.state = state;
            assert!(dkg.verify_message(&sender, &announce, rng).is_err());
            assert!(dkg
                .apply_message(sender.clone(), announce.clone())
                .is_err());
        }
    }
}

/// Test the dealing phase of the DKG
#[cfg(test)]
mod test_dealing {
    use super::test_common::*;
    use crate::DkgState::Dealt;

    /// Test that dealing correct PVSS transcripts
    /// pass verification an application and that
    /// state is updated correctly
    #[test]
    fn test_pvss_dealing() {
        let rng = &mut ark_std::test_rng();
        // gather everyone's transcripts
        let mut transcripts = vec![];
        for i in 0..4 {
            let mut dkg = setup_shared_dkg(i);
            transcripts.push(dkg.share(rng).expect("Test failed"));
        }
        // our test dkg
        let mut dkg = setup_shared_dkg(0);
        // iterate over transcripts from lowest weight to highest
        let mut expected = 0u32;
        for (sender, pvss) in transcripts.into_iter().rev().enumerate() {
            // check the verification passes
            assert!(dkg
                .verify_message(
                    &dkg.validator_set.validators[3 - sender],
                    &pvss,
                    rng
                )
                .is_ok());
            // check that application passes
            assert!(dkg
                .apply_message(
                    dkg.validator_set.validators[3 - sender].clone(),
                    pvss
                )
                .is_ok());
            expected += dkg.validator_set.validators[3 - sender].power as u32;
            if sender < 3 {
                // check that weight accumulates correctly
                match dkg.state {
                    DkgState::Shared { accumulated_weight } => {
                        assert_eq!(accumulated_weight, expected)
                    }
                    _ => panic!("Test failed"),
                }
            } else {
                // check that when enough weight is accumulated, we transition state
                assert!(matches!(dkg.state, DkgState::Dealt));
            }
        }
    }

    /// Test the verification and application of
    /// pvss transcripts from unknown validators
    /// are rejected
    #[test]
    fn test_pvss_from_unknown_dealer_rejected() {
        let rng = &mut ark_std::test_rng();
        let mut dkg = setup_shared_dkg(0);
        assert!(matches!(
            dkg.state,
            DkgState::Shared {
                accumulated_weight: 0
            }
        ));
        let pvss = dkg.share(rng).expect("Test failed");
        let sender = TendermintValidator {
            power: 9001,
            address: "Goku".into(),
        };
        // check that verification fails
        assert!(dkg.verify_message(&sender, &pvss, rng).is_err());
        // check that application fails
        assert!(dkg.apply_message(sender, pvss).is_err());
        // check that state has not changed
        assert!(matches!(
            dkg.state,
            DkgState::Shared {
                accumulated_weight: 3
            }
        ));
    }

    /// Test that if a validator sends two pvss transcripts,
    /// the second fails to verify
    #[test]
    fn test_pvss_sent_twice_rejected() {
        let rng = &mut ark_std::test_rng();
        let mut dkg = setup_shared_dkg(0);
        assert!(matches!(
            dkg.state,
            DkgState::Shared {
                accumulated_weight: 0
            }
        ));
        let pvss = dkg.share(rng).expect("Test failed");
        let sender = dkg.validator_set.validators[3].clone();
        // check that verification fails
        assert!(dkg.verify_message(&sender, &pvss, rng).is_ok());
        // check that application fails
        assert!(dkg.apply_message(sender.clone(), pvss.clone()).is_ok());
        // check that state has appropriately changed
        assert!(matches!(
            dkg.state,
            DkgState::Shared {
                accumulated_weight: 3
            }
        ));
        // check that sending another pvss from same sender fails
        assert!(dkg.verify_message(&sender, &pvss, rng).is_err());
    }

    /// Test that if a validators tries to verify it's own
    /// share message, it fails
    #[test]
    fn test_pvss_rejects_own_pvss() {
        let rng = &mut ark_std::test_rng();
        let mut dkg = setup_shared_dkg(0);
        assert!(matches!(
            dkg.state,
            DkgState::Shared {
                accumulated_weight: 0
            }
        ));
        // create share message and check state update
        let pvss = dkg.share(rng).expect("Test failed");
        assert!(matches!(
            dkg.state,
            DkgState::Shared {
                accumulated_weight: 3
            }
        ));
        let sender = dkg.validator_set.validators[0].clone();
        // check that verification fails
        assert!(dkg.verify_message(&sender, &pvss, rng).is_err());
        // check that state did not change
        assert!(matches!(
            dkg.state,
            DkgState::Shared {
                accumulated_weight: 3
            }
        ));
    }

    /// Test that the [`PubliclyVerifiableDkg<E>::share`] method
    /// errors if its state is not [`DkgState::Shared{..} | Dkg::Dealt`]
    #[test]
    fn test_pvss_cannot_share_from_wrong_state() {
        let rng = &mut ark_std::test_rng();
        let mut dkg = setup_shared_dkg(0);
        assert!(matches!(
            dkg.state,
            DkgState::Shared {
                accumulated_weight: 0
            }
        ));
        for state in vec![
            DkgState::Init { announced: 0 },
            DkgState::Success {
                final_key: G1::zero(),
            },
        ] {
            dkg.state = state;
            assert!(dkg.share(rng).is_err());
        }
        // check that even if security threshold is met, we can still share
        dkg.state = DkgState::Dealt;
        assert!(dkg.share(rng).is_ok());
    }

    /// Check that share messages can only be
    /// verified or applied if the dkg is in
    /// state [`DkgState::Share{..} | DkgState::Dealt`]
    #[test]
    fn test_share_message_state_guards() {
        let rng = &mut ark_std::test_rng();
        let mut dkg = setup_shared_dkg(0);
        let pvss = dkg.share(rng).expect("Test failed");
        assert!(matches!(
            dkg.state,
            DkgState::Shared {
                accumulated_weight: 3
            }
        ));
        let sender = dkg.validator_set.validators[3].clone();
        for state in vec![
            DkgState::Init { announced: 0 },
            DkgState::Success {
                final_key: G1::zero(),
            },
        ] {
            dkg.state = state;
            assert!(dkg.verify_message(&sender, &pvss, rng).is_err());
            assert!(dkg.apply_message(sender.clone(), pvss.clone()).is_err());
        }
        // check that we can still accept pvss transcripts after meeting threshold
        dkg.state = DkgState::Dealt;
        assert!(dkg.verify_message(&sender, &pvss, rng).is_ok());
        assert!(dkg.apply_message(sender, pvss).is_ok());
        assert!(matches!(dkg.state, DkgState::Dealt))
    }
}

/// Test aggregating transcripts into final key
#[cfg(test)]
mod test_aggregation {
    use super::test_common::*;

    /// Test that if the security threshold is
    /// met, we can create a final key
    #[test]
    fn test_aggregate() {
        let rng = &mut ark_std::test_rng();
        let mut dkg = setup_dealt_dkg();
        let aggregate = dkg.aggregate().expect("Test failed");
        let sender = dkg.validator_set.validators[dkg.me].clone();
        assert!(dkg.verify_message(&sender, &aggregate, rng).is_ok());
        assert!(dkg.apply_message(sender, aggregate).is_ok());
        assert!(matches!(dkg.state, DkgState::Success { .. }));
    }

    /// Test that aggregate only succeeds if we are in
    /// the state [`DkgState::Dealt | DkgState::Success{..}`]
    #[test]
    fn test_aggregate_state_guards() {
        let mut dkg = setup_dealt_dkg();
        for state in vec![
            DkgState::Init { announced: 0 },
            DkgState::Shared {
                accumulated_weight: 0,
            },
        ] {
            dkg.state = state;
            assert!(dkg.aggregate().is_err())
        }
        dkg.state = DkgState::Success {
            final_key: G1::zero(),
        };
        assert!(dkg.aggregate().is_ok());
    }

    /// Test that aggregate message fail to be verified
    /// or applied unless dkg.state is
    /// [`DkgState::Dealt | DkgState::Success{..}`]
    #[test]
    fn test_aggregate_message_state_guards() {
        let rng = &mut ark_std::test_rng();
        let mut dkg = setup_dealt_dkg();
        let aggregate = dkg.aggregate().expect("Test failed");
        let sender = dkg.validator_set.validators[dkg.me].clone();
        for state in vec![
            DkgState::Init { announced: 0 },
            DkgState::Shared {
                accumulated_weight: 0,
            },
        ] {
            dkg.state = state;
            assert!(dkg.verify_message(&sender, &aggregate, rng).is_err());
            assert!(dkg
                .apply_message(sender.clone(), aggregate.clone())
                .is_err())
        }
        dkg.state = DkgState::Success {
            final_key: G1::zero(),
        };
        assert!(dkg.verify_message(&sender, &aggregate, rng).is_ok());
        assert!(dkg.apply_message(sender, aggregate).is_ok())
    }

    /// Test that an aggregate message will fail to verify if the
    /// security threshold is not met
    #[test]
    fn test_aggregate_wont_verify_if_under_threshold() {
        let rng = &mut ark_std::test_rng();
        let mut dkg = setup_dealt_dkg();
        dkg.params.total_weight = 10;
        let aggregate = dkg.aggregate().expect("Test failed");
        let sender = dkg.validator_set.validators[dkg.me].clone();
        assert!(dkg.verify_message(&sender, &aggregate, rng).is_err());
    }
}
