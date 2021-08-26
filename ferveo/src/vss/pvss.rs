use crate::*;
use ark_ec::PairingEngine;
use ark_serialize::*;
use itertools::Itertools;

pub type ShareEncryptions<E> = Vec<<E as PairingEngine>::G2Affine>;

/// The dealer posts the Dealing to the blockchain to initiate the VSS
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct PubliclyVerifiableSS<E: PairingEngine> {
    /// Feldman commitment to the VSS polynomial, F = g^{\phi}
    pub coeffs: Vec<E::G1Affine>,

    // \hat{u}_2 = \hat{u}_1^{a_0}
    pub u_hat_2: E::G2Affine,

    // ek_i^{f(\omega_j)}
    pub shares: Vec<ShareEncryptions<E>>,

    // Proof of Knowledge
    pub sigma: E::G2Affine,

    // A_i
    pub commitment: Vec<E::G1Affine>,
}

#[derive(Clone)]
pub struct PubliclyVerifiableParams<E: PairingEngine> {
    pub g_1: E::G1Projective,
    pub u_hat_1: E::G2Affine,
}

impl<E> PubliclyVerifiableSS<E>
where
    E: PairingEngine,
{
    /// Verify that this PVSS instance is a valid aggregation of
    /// the PVSS instances, produced by `aggregate`,
    /// and received by the DKG context `dkg`
    /// Returns the total valid weight of the aggregated PVSS,
    ///  and the local private keyshares
    pub fn verify_aggregation(
        &self,
        dkg: &PubliclyVerifiableDkg<E>,
    ) -> Result<(u32, Vec<E::G2Affine>)> {
        print_time!("PVSS verify_aggregation");
        let local_shares = self.verify(dkg)?;
        let mut y = E::G1Projective::zero();
        let mut weight = 0u32;
        for (dealer, pvss) in dkg.vss.iter() {
            let c = pvss.coeffs[0].into_projective();
            if E::pairing(c, E::G2Affine::prime_subgroup_generator())
                != E::pairing(
                    E::G1Affine::prime_subgroup_generator(),
                    pvss.sigma,
                )
            {
                return Err(anyhow!("PVSS sigma verification"));
            }
            y += c;
            weight += dkg.participants[*dealer as usize].weight;
        }
        if y.into_affine() == self.coeffs[0] {
            Ok((weight, local_shares))
        } else {
            Err(anyhow!(
                "aggregation does not match received PVSS instances"
            ))
        }
    }

    /// Aggregate the PVSS instances in `pvss` from DKG session `dkg` ]
    /// into a new PVSS instance
    pub fn aggregate(
        dkg: &PubliclyVerifiableDkg<E>,
        pvss: &BTreeMap<u32, PubliclyVerifiableSS<E>>,
    ) -> Self {
        let mut pvss_iter = pvss.iter();
        let (_, first_pvss) = pvss_iter.next().unwrap(); //TODO: unwrap?
        let mut coeffs = batch_to_projective(&first_pvss.coeffs);

        let mut u_hat_2 = first_pvss.u_hat_2.into_projective();

        let mut shares = first_pvss
            .shares
            .iter()
            .map(|a| batch_to_projective(a))
            .collect::<Vec<_>>();
        for (_, next) in pvss_iter {
            for (a, b) in coeffs.iter_mut().zip_eq(next.coeffs.iter()) {
                *a += b.into_projective();
            }
            u_hat_2 += next.u_hat_2.into_projective();
            for (a, b) in shares.iter_mut().zip_eq(next.shares.iter()) {
                for (c, d) in a.iter_mut().zip_eq(b.iter()) {
                    *c += d.into_projective();
                }
            }
        }
        let shares = shares
            .iter()
            .map(|a| E::G2Projective::batch_normalization_into_affine(&a))
            .collect::<Vec<_>>();

        let sigma = E::G2Affine::zero();

        let mut commitment = coeffs.clone();
        {
            print_time!("commitment fft");
            dkg.domain.fft_in_place(&mut commitment);
        }
        Self {
            coeffs: E::G1Projective::batch_normalization_into_affine(&coeffs),
            u_hat_2: u_hat_2.into_affine(),
            shares,
            sigma,
            commitment: E::G1Projective::batch_normalization_into_affine(
                &commitment,
            ),
        }
    }
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
        let coeffs = fast_multiexp(&phi.coeffs, dkg.pvss_params.g_1);

        let shares = dkg
            .participants
            .iter()
            .map(|participant| {
                let share_range = participant.share_range.clone();

                fast_multiexp(
                    &evals.evals[share_range],
                    participant.session_key.encryption_key.into_projective(),
                )
            })
            .collect::<Vec<ShareEncryptions<E>>>();

        //phi.zeroize(); // TODO zeroize?

        let u_hat_2 = dkg.pvss_params.u_hat_1.mul(*s).into_affine(); //TODO: new base

        let sigma = E::G2Affine::prime_subgroup_generator().mul(*s).into(); //todo hash to curve

        let vss = Self {
            coeffs,
            u_hat_2,
            shares,
            sigma,
            commitment: vec![], // Optimistically avoid computing the commitment
        };

        Ok(vss)
    }

    /// Verify the PVSS instance `self` is a valid PVSS instance for the DKG context `dkg`
    pub fn verify(
        &self,
        dkg: &PubliclyVerifiableDkg<E>,
    ) -> Result<Vec<E::G2Affine>> {
        print_time!("PVSS verify");

        let _me = &dkg.participants[dkg.me as usize];

        if self.shares.len() != dkg.participants.len() {
            return Err(anyhow!("wrong vss length"));
        }

        //let pairings = vec![];
        //let random_coefficients = vec![];
        // check e(F_0, u_hat_1) == e(g_1, u_hat_2)
        if E::pairing(self.coeffs[0], dkg.pvss_params.u_hat_1)
            != E::pairing(dkg.pvss_params.g_1, self.u_hat_2)
        {
            return Err(anyhow!("invalid"));
        }
        {
            print_time!("check encryptions");
            //check e()
            dkg.participants.iter().zip(self.shares.iter()).all(
                |(participant, shares)| {
                    let share_range = participant.share_range.clone();
                    let ek = participant.session_key.encryption_key;
                    let alpha = E::Fr::one(); //TODO: random number!
                    let mut powers_of_alpha = alpha;
                    let mut y = E::G2Projective::zero();
                    let mut a = E::G1Projective::zero();
                    for (y_i, a_i) in shares
                        .iter()
                        .zip_eq(self.commitment[share_range].iter())
                    {
                        y += y_i.mul(powers_of_alpha);
                        a += a_i.mul(powers_of_alpha);
                        powers_of_alpha *= alpha;
                    }

                    E::pairing(dkg.pvss_params.g_1, y) == E::pairing(a, ek)
                },
            );
        }

        let local_shares = {
            print_time!("decrypt shares");

            self.shares[dkg.me]
                .iter()
                .map(|p| p.mul(dkg.session_keypair.decryption_key))
                .collect::<Vec<_>>()
        };
        Ok(E::G2Projective::batch_normalization_into_affine(
            &local_shares,
        ))
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
    let rng = &mut ark_std::test_rng();
    use ark_bls12_381::Bls12_381;
    type Fr = <Bls12_381 as PairingEngine>::Fr;
    type G1 = <Bls12_381 as PairingEngine>::G1Affine;
    type G2 = <Bls12_381 as PairingEngine>::G2Affine;

    let phi = DensePolynomial::<Fr>::rand(8192 / 3, rng);
    let domain = ark_poly::Radix2EvaluationDomain::<Fr>::new(8192)
        .ok_or_else(|| anyhow!("unable to construct domain"))
        .unwrap();

    let evals = phi.evaluate_over_domain_by_ref(domain);

    let g_1 = G1::prime_subgroup_generator();
    // commitment to coeffs
    let _coeffs = fast_multiexp(&phi.coeffs, g_1.into_projective());

    let weight = 8192 / 150;
    let _shares = (0..150)
        .map(|participant| {
            let share_range =
                (participant * weight)..((participant + 1) * weight);

            fast_multiexp(
                &evals.evals[share_range],
                G2::prime_subgroup_generator().into_projective(),
            )
        })
        .collect::<Vec<_>>();
}
