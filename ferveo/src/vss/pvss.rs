use crate::*;
use ark_ec::PairingEngine;
use ark_serialize::*;
use itertools::Itertools;
use std::collections::BTreeMap;
use ferveo_common::{ValidatorPublicKey, PublicKey};

/// These are the evaluations of weight shares of a single random polynomial
pub type ShareEncryptions<E> = Vec<<E as PairingEngine>::G2Affine>;

/// Each validator posts a transcript to the chain. Once enough
/// validators have done this (their total voting power exceeds
/// 2/3 the total), this will be aggregated into a final key
///
/// *IMPORTANT* These messages must be signed
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct PubliclyVerifiableSS<E: PairingEngine> {
    /// the session public key for the issuing validator
    pub(crate) public_key: PublicKey<E>,

    /// Feldman commitment to the VSS polynomial, F = g^{\phi}
    pub coeffs: Vec<E::G1Affine>,

    /// ek_i^{f(\omega_j)}
    pub shares: ShareEncryptions<E>,

    /// Proof of Knowledge
    pub sigma: E::G2Affine,
}

/// This attempts to aggregate individual PVSS transcripts
/// so that verifications can be run in bulk more efficiently.
/// If this succeeds and the weight is sufficient, we can
/// produce the final key.
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct AggregatePubliclyVerifiableSS<E: PairingEngine> {
    /// Feldman commitment to the VSS polynomial, F = g^{\phi}
    pub coeffs: Vec<E::G1Affine>,

    /// ek_i^{f(\omega_j)}
    pub shares: ShareEncryptions<E>,

    /// Proof of Knowledge
    pub sigma: E::G2Affine,

    /// A_i
    pub commitment: Vec<E::G1Affine>,
}

#[derive(Clone)]
pub struct PubliclyVerifiableParams<E: PairingEngine> {
    pub g: E::G1Projective,
    pub h: E::G2Projective,
}

impl <E: PairingEngine> PubliclyVerifiableSS<E> {

    /// Create a new PVSS instance
    /// `s`: the secret constant coefficient to share
    /// `dkg`: the current DKG session
    /// `rng` a cryptographic random number generator
    pub fn new<R: Rng>(
        s: &E::Fr,
        dkg: &PubliclyVerifiableDkg<E>,
        rng: &mut R,
    ) -> Result<Self> {
        let mut phi = DensePolynomial::<E::Fr>::rand(
            dkg.params.security_threshold as usize,
            rng,
        );
        phi.coeffs[0] = *s;

        let evals = phi.evaluate_over_domain_by_ref(dkg.domain);

        // commitment to coeffs
        let coeffs = fast_multiexp(&phi.coeffs, dkg.pvss_params.g);
        let validator = &dkg.validators[dkg.me];
        let key = match validator.key {
            ValidatorPublicKey::Announced(key) => Ok(key),
            _ => Err(
                anyhow!("An session keypair was not generated for the owner of this dkg instance")
            )
        }?;
        let shares = fast_multiexp(
            &evals.evals[validator.share_start..validator.share_end],
            key.encryption_key.into_projective(),
        )
        .into_iter()
        .collect::<ShareEncryptions<E>>();

        //phi.zeroize(); // TODO zeroize?

        let sigma = E::G2Affine::prime_subgroup_generator().mul(*s).into(); //todo hash to curve

        let vss = Self {
            public_key: dkg.session_keypair.public(),
            coeffs,
            shares,
            sigma,
        };

        Ok(vss)
    }

    /// Verify the pvss transcript from a validator. This is not the full check,
    /// i.e. we optimistically do not check the commitment. This is deferred
    /// until the aggregation step
    pub fn verify_optimistic(&self) -> bool {
        E::pairing(self.coeffs[0].into_projective(), E::G2Affine::prime_subgroup_generator())
            == E::pairing(
            E::G1Affine::prime_subgroup_generator(),
            self.sigma,
        )
    }

    /// If aggregation fails, a validator needs to know that their pvss
    /// transcript was at fault so that the can issue a new one. This
    /// performs the full check.
    pub fn verify_full(
        &self,
        dkg: &PubliclyVerifiableDkg<E>,
        commitment: Option<&[E::G1Affine]>
    ) -> bool {
        let pred = | commitment: &[E::G1Affine] |
            {
                let ek = self.public_key.encryption_key;
                let alpha = E::Fr::one(); //TODO: random number!
                let mut powers_of_alpha = alpha;
                let mut y = E::G2Projective::zero();
                let mut a = E::G1Projective::zero();
                for (y_i, a_i) in self.shares
                    .iter()
                    .zip_eq(commitment.iter())
                {
                    y += y_i.mul(powers_of_alpha);
                    a += a_i.mul(powers_of_alpha);
                    powers_of_alpha *= alpha;
                }
                E::pairing(dkg.pvss_params.g, y) == E::pairing(a, ek)
            };
        match commitment {
            Some(commitment) => pred(commitment),
            None => {
                let mut commitment = batch_to_projective(&self.coeffs);
                print_time!("commitment fft");
                dkg.domain.fft_in_place(&mut commitment);
                pred(&E::G1Projective::batch_normalization_into_affine(&commitment))
            }
        }
    }
}

/// Aggregate the PVSS instances in `pvss` from DKG session `dkg`
/// into a new PVSS instance
pub fn aggregate<E: PairingEngine>(
    dkg: &PubliclyVerifiableDkg<E>,
    pvss: &BTreeMap<u32, PubliclyVerifiableSS<E>>,
) -> AggregatePubliclyVerifiableSS<E> {
    let mut pvss_iter = pvss.iter();
    let (_, first_pvss) = pvss_iter.next().unwrap();
    let mut coeffs = batch_to_projective(&first_pvss.coeffs);

    let mut shares = batch_to_projective(&first_pvss.shares);
    for (_, next) in pvss_iter {
        for (a, b) in coeffs.iter_mut().zip_eq(next.coeffs.iter()) {
            *a += b.into_projective();
        }
        for (a, b) in shares.iter_mut().zip_eq(next.shares.iter()) {
            *a += b.into_projective();
        }
    }
    let shares = E::G2Projective::batch_normalization_into_affine(&shares);

    let sigma = E::G2Affine::zero();

    let mut commitment = coeffs.clone();
    {
        print_time!("commitment fft");
        dkg.domain.fft_in_place(&mut commitment);
    }
    AggregatePubliclyVerifiableSS {
        coeffs: E::G1Projective::batch_normalization_into_affine(&coeffs),
        shares,
        sigma,
        commitment: E::G1Projective::batch_normalization_into_affine(
            &commitment,
        ),
    }
}

impl<E: PairingEngine> AggregatePubliclyVerifiableSS<E> {
    /// Verify that this PVSS instance is a valid aggregation of
    /// the PVSS instances, produced by [`aggregate`],
    /// and received by the DKG context `dkg`
    /// Returns the total valid weight of the aggregated PVSS
    pub fn verify_aggregation(
        &self,
        dkg: &PubliclyVerifiableDkg<E>,
    ) -> Result<u32> {
        print_time!("PVSS verify_aggregation");
        self.verify(dkg);
        let mut y = E::G1Projective::zero();
        let mut weight = 0u32;
        for (dealer, pvss) in dkg.vss.iter() {
            y += pvss.coeffs[0].into_projective();
            weight += dkg.validators[*dealer as usize].weight;
        }
        if y.into_affine() == self.coeffs[0] {
            Ok(weight)
        } else {
            Err(anyhow!(
                "aggregation does not match received PVSS instances"
            ))
        }
    }

    /// We check the batched commitments of the constituent pvss
    /// transcripts
    pub fn verify(&self, dkg: &PubliclyVerifiableDkg<E>) -> bool {
        print_time!("PVSS verify");
        print_time!("check encryptions");
        dkg.vss.iter().all(
            |(validator_ix, pvss)| {
                let validator = dkg.validators.get(*validator_ix as usize).unwrap();
                pvss.verify_full(
                    &dkg,
                    Some(&self.commitment[validator.share_start..validator.share_end])
                )
            }
        )
    }
}


/*
#[test]
fn test_pvss() {
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
}*/

#[test]
fn test_pvss() {
    let mut rng = &mut ark_std::test_rng();
    use ark_bls12_381::Bls12_381;
    type Fr = <Bls12_381 as PairingEngine>::Fr;
    type G1 = <Bls12_381 as PairingEngine>::G1Affine;
    type G2 = <Bls12_381 as PairingEngine>::G2Affine;

    let mut phi = DensePolynomial::<Fr>::rand(2 * 128 / 3, &mut rng);
    //use ark_std::UniformRand;
    let domain = ark_poly::Radix2EvaluationDomain::<Fr>::new(8192)
        .ok_or_else(|| anyhow!("unable to construct domain"))
        .unwrap();

    let evals = phi.evaluate_over_domain_by_ref(domain);

    let g_1 = G1::prime_subgroup_generator();
    // commitment to coeffs
    let _coeffs = fast_multiexp(&phi.coeffs, g_1.into_projective());

    let weight = 128 / 4;
    let shares = (0..4)
        .map(|participant| {
            let share_range =
                (participant * weight)..((participant + 1) * weight);

            fast_multiexp(
                &evals.evals[share_range],
                G2::prime_subgroup_generator().into_projective(),
            )
        })
        .collect::<Vec<_>>();

    // use group_threshold_cryptography::*;
    // // let mut rng = test_rng
    // let shares_num = 8192;();
    // let threshold = shares_num*2/3;
    // let num_entities = 150;

    // let msg: &[u8] = "abc".as_bytes();

    // // let (pubkey, privkey, _) = setup::<Bls12_381>(threshold, shares_num, num_entities);

    // let ciphertext = encrypt::<ark_std::rand::rngs::StdRng, Bls12_381>(msg, pubkey, &mut rng);
    // let plaintext = decrypt(&ciphertext, privkey);

    // assert!(msg == plaintext)
}
