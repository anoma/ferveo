use crate::*;

/// The Context of an individual VSS instance as either the Dealer or the Dealee
#[derive(Debug)]
pub struct FeldmanVSS<Affine: AffineCurve> {
    pub dealer: u32,
    pub encrypted_shares: FeldmanSharingMsg<Affine>,
    pub state: VSSState<Affine>,
    pub local_shares: Vec<Affine::ScalarField>,
    pub ready_msg: Vec<ed25519_dalek::PublicKey>, //TODO: Should be a set, but doesn't support comparison ops
    pub finalize_msg: Option<FeldmanFinalizeMsg<Affine>>,
}

/// The dealer posts the Dealing to the blockchain to initiate the VSS
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FeldmanSharingMsg<Affine: AffineCurve> {
    /// Commitment to the VSS polynomial, g^{\phi}
    #[serde(with = "crate::ark_serde")]
    pub coeffs: Vec<Affine>,

    /// The encrypted shares for each participant
    pub shares: Vec<NodeSharesCiphertext>,
}

//TODO: Is the entire ready message necessary at all or do we just have a dispute timeout?
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct FeldmanReadyMsg {
    pub dealer: u32,
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
#[serde(bound = "")]
pub struct FeldmanFinalizeMsg<Affine: AffineCurve> {
    //TODO: necessary?
    #[serde(with = "crate::ark_serde")]
    pub rebased_secret: Affine,
    pub proof: NIZKP<Affine>,
}

impl<Affine> FeldmanVSS<Affine>
where
    Affine: AffineCurve,
{
    pub fn handle_ready(
        &mut self,
        signer: &ed25519_dalek::PublicKey,
        ready: &FeldmanReadyMsg,
        signer_weight: u32,
    ) -> Result<u32> {
        if let VSSState::Sharing { weight_ready } = self.state {
            if self.ready_msg.contains(&signer) {
                return Err(anyhow::anyhow!("Duplicate ready message"));
            } else {
                self.ready_msg.push(*signer);
                self.state = VSSState::Sharing {
                    weight_ready: weight_ready + signer_weight,
                };
                return Ok(weight_ready + signer_weight);
            }
        }
        Ok(0u32) //TODO: better return possible?
    }

    pub fn handle_finalize(
        &mut self,
        finalize: &FeldmanFinalizeMsg<Affine>,
        minimum_ready_weight: u32,
        g: &Affine,
    ) -> Result<()> {
        if let VSSState::Sharing { weight_ready } = self.state {
            if weight_ready >= minimum_ready_weight {
                if finalize.proof.dleq_verify(
                    &g,
                    &self.encrypted_shares.coeffs[0],
                    &Affine::prime_subgroup_generator(),
                    &finalize.rebased_secret,
                ) {
                    self.state = VSSState::Success {
                        final_secret: finalize.rebased_secret,
                    };
                    Ok(())
                } else {
                    Err(anyhow::anyhow!(
                        "FinalizeMsg: bad rebased secret proof"
                    ))
                }
            } else {
                Err(anyhow::anyhow!("FinalizeMsg: dealer was early"))
            }
        } else {
            Err(anyhow::anyhow!("FinalizeMsg: not currently sharing"))
        }
    }

    pub fn new<R: Rng>(
        s: &Affine::ScalarField,
        dkg: &PedersenDKG<Affine>,
        rng: &mut R,
    ) -> Result<Self> {
        let mut phi = DensePolynomial::<Affine::ScalarField>::rand(
            dkg.params.security_threshold as usize,
            rng,
        );
        phi.coeffs[0] = *s;

        let evals = phi.evaluate_over_domain_by_ref(dkg.domain);

        // commitment to coeffs
        let coeffs = fast_multiexp(
            &phi.coeffs,
            Affine::Projective::prime_subgroup_generator(),
        );

        let shares = dkg
            .participants
            .iter()
            .filter_map(|participant| {
                if participant.ed_key == dkg.ed_key.public {
                    None
                } else {
                    let shares = &evals.evals[participant.share_range.clone()];

                    Some(
                        NodeSharesPlaintext::<Affine> {
                            shares: shares.to_vec(), // TODO: possible eliminate the copy?
                        }
                        .encrypt(
                            &dkg.session_keypair
                                .encrypt_cipher(&participant.session_key),
                        ),
                    )
                }
            })
            .collect::<Vec<_>>();

        //phi.zeroize(); // TODO zeroize?

        let rebased_secret = Affine::prime_subgroup_generator().mul(*s).into(); //TODO: new base
        let proof = NIZKP::<Affine>::dleq(
            &Affine::prime_subgroup_generator(),
            &coeffs[0],
            &Affine::prime_subgroup_generator(),
            &rebased_secret,
            &s,
            rng,
        );
        let vss = Self {
            dealer: dkg.me as u32,
            encrypted_shares: FeldmanSharingMsg { coeffs, shares },
            state: VSSState::Sharing { weight_ready: 0u32 },
            local_shares: evals.evals
                [dkg.participants[dkg.me].share_range.clone()]
            .to_vec(),
            finalize_msg: Some(FeldmanFinalizeMsg {
                rebased_secret,
                proof,
            }),
            ready_msg: vec![],
        };

        Ok(vss)
    }
    pub fn recv(
        dealer: u32,
        encrypted_shares: &FeldmanSharingMsg<Affine>,
        dkg: &PedersenDKG<Affine>,
    ) -> Result<Self> {
        let me = &dkg.participants[dkg.me as usize];

        if encrypted_shares.shares.len() != dkg.participants.len() - 1 {
            return Err(anyhow!("wrong vss length"));
        }
        let adjusted_index =
            dkg.me - if dkg.me > dealer as usize { 1 } else { 0 };

        let local_shares = encrypted_shares.shares[adjusted_index]
            .decrypt::<Affine>(&dkg.session_keypair.decrypt_cipher(
                &dkg.participants[dealer as usize].session_key,
            ))?;

        //dbg!(local_shares.shares[0]);

        let mut commitment = encrypted_shares
            .coeffs
            .iter()
            .map(|p| p.into_projective())
            .collect::<Vec<_>>();
        dkg.domain.fft_in_place(&mut commitment);

        let commitment =
            Affine::Projective::batch_normalization_into_affine(&commitment);

        // TODO: is it faster to do the multiexp first, then the FFT?
        let shares_commitment = fast_multiexp(
            &local_shares.shares,
            Affine::Projective::prime_subgroup_generator(),
        );

        for (i, j) in commitment[dkg.participants[dkg.me].share_range.clone()]
            .iter()
            .zip(shares_commitment.iter())
        {
            if *i != *j {
                return Err(anyhow!("share opening proof invalid"));
            }
        }

        Ok(Self {
            dealer,
            encrypted_shares: encrypted_shares.clone(),
            state: VSSState::Sharing { weight_ready: 0u32 },
            local_shares: local_shares.shares,
            finalize_msg: None,
            ready_msg: vec![],
        })
    }
    fn deal(&self) -> FeldmanSharingMsg<Affine> {
        self.encrypted_shares.clone()
    }
}

#[test]
fn test_feldman() {
    let rng = &mut ark_std::test_rng();
    type Affine = ark_pallas::Affine;
    type Scalar = <Affine as AffineCurve>::ScalarField;
    let mut phi = DensePolynomial::<Scalar>::rand(2, rng);
    let domain = ark_poly::Radix2EvaluationDomain::<Scalar>::new(4 as usize)
        .ok_or_else(|| anyhow!("unable to construct domain"))
        .unwrap();

    let evals = phi.evaluate_over_domain_by_ref(domain);

    // commitment to coeffs
    let coeffs = fast_multiexp(
        &evals.evals,
        <Affine as AffineCurve>::Projective::prime_subgroup_generator(),
    );

    let shares = (0..2usize)
        .map(|participant| evals.evals[participant])
        .collect::<Vec<_>>();

    let mut commitment = coeffs
        .iter()
        .map(|p| p.into_projective())
        .collect::<Vec<_>>();
    domain.fft_in_place(&mut commitment);

    let commitment =
        <Affine as AffineCurve>::Projective::batch_normalization_into_affine(
            &commitment,
        );

    // TODO: is it faster to do the multiexp first, then the FFT?
    let shares_commitment = fast_multiexp(
        &shares,
        <Affine as AffineCurve>::Projective::prime_subgroup_generator(),
    );
    assert_eq!(
        commitment[0],
        Affine::prime_subgroup_generator()
            .mul(shares[0])
            .into_affine()
    );
}
