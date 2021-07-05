use crate::*;
use ark_ec::PairingEngine;
use itertools::Itertools;
use serde::*;

pub type ShareEncryptions<E: PairingEngine> = Vec<E::G2Affine>;

/// The dealer posts the Dealing to the blockchain to initiate the VSS
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PubliclyVerifiableSS<E: PairingEngine> {
    /// Feldman commitment to the VSS polynomial, F = g^{\phi}
    #[serde(with = "crate::ark_serde")]
    pub coeffs: Vec<E::G1Affine>,

    // \hat{u}_2 = \hat{u}_1^{a_0}
    #[serde(with = "crate::ark_serde")]
    pub u_hat_2: E::G2Affine,

    // ek_i^{f(\omega_j)}
    #[serde(with = "crate::ark_serde")]
    pub shares: Vec<ShareEncryptions<E>>,

    // Signature of Knowledge
    #[serde(with = "crate::ark_serde")]
    pub sigma: (E::G2Affine, E::G2Affine),
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
    pub fn verify_aggregation(
        &self,
        dkg: &PubliclyVerifiableDKG<E>,
    ) -> Result<u32> {
        self.verify(dkg)?;
        let mut Y = E::G1Projective::zero();
        let mut weight = 0u32;
        for (dealer, pvss) in dkg.vss.iter() {
            Y += pvss.coeffs[0].into_projective();
            weight += dkg.participants[*dealer as usize].weight;
        }
        if Y.into_affine() == self.coeffs[0] {
            Ok(weight)
        } else {
            Err(anyhow!(
                "aggregation does not match received PVSS instances"
            ))
        }
    }

    pub fn aggregate(
        dkg: &PubliclyVerifiableDKG<E>,
        pvss: &[PubliclyVerifiableSS<E>],
    ) -> Self {
        let mut coeffs = batch_to_projective(&pvss[0].coeffs);

        let mut u_hat_2 = pvss[0].u_hat_2.into_projective();

        let mut shares = pvss[0]
            .shares
            .iter()
            .map(|a| batch_to_projective(a))
            .collect::<Vec<_>>();
        for next in pvss[1..].iter() {
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

        let sigma = (E::G2Affine::zero(), E::G2Affine::zero());
        Self {
            coeffs: E::G1Projective::batch_normalization_into_affine(&coeffs),
            u_hat_2: u_hat_2.into_affine(),
            shares,
            sigma,
        }
    }

    pub fn new<R: Rng>(
        s: &E::Fr,
        dkg: &PubliclyVerifiableDKG<E>,
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

        let sigma = (
            E::G2Affine::prime_subgroup_generator().mul(*s).into(), //todo hash to curve
            E::G2Affine::prime_subgroup_generator()
                .mul(dkg.session_keypair.signing_key)
                .into(),
        );

        let vss = Self {
            coeffs,
            u_hat_2,
            shares,
            sigma,
        };

        Ok(vss)
    }
    pub fn verify(
        &self,
        //dealer: u32,
        //encrypted_shares: &PubliclyVerifiableSharingMsg<E>,
        dkg: &PubliclyVerifiableDKG<E>,
    ) -> Result<()> {
        let me = &dkg.participants[dkg.me as usize];

        if self.shares.len() != dkg.participants.len() {
            return Err(anyhow!("wrong vss length"));
        }

        {
            print_time!("decrypt shares");

            let local_shares = self.shares[dkg.me]
                .iter()
                .map(|p| p.mul(dkg.session_keypair.decryption_key))
                .collect::<Vec<_>>();
        }
        let mut commitment = self
            .coeffs
            .iter()
            .map(|p| p.into_projective())
            .collect::<Vec<_>>();
        {
            print_time!("commitment fft");
            dkg.domain.fft_in_place(&mut commitment);
        }

        // check e(F_0, u_hat_1) == e(g_1, u_hat_2)
        if E::pairing(self.coeffs[0], dkg.pvss_params.u_hat_1)
            != E::pairing(dkg.pvss_params.g_1, self.u_hat_2)
        {
            return Err(anyhow!("invalid"));
        }
        print_time!("check encryptions");
        //check e()
        dkg.participants.iter().zip(self.shares.iter()).all(
            |(participant, shares)| {
                let share_range = participant.share_range.clone();
                let ek = participant.session_key.encryption_key;
                let alpha = E::Fr::one(); //TODO: random number!
                let mut powers_of_alpha = alpha;
                let mut Y = E::G2Projective::zero();
                let mut A = E::G1Projective::zero();
                for (Y_i, A_i) in
                    shares.iter().zip(commitment[share_range].iter())
                {
                    Y += Y_i.mul(powers_of_alpha);
                    A += A_i.into_affine().mul(powers_of_alpha);
                    powers_of_alpha *= alpha;
                }

                E::pairing(dkg.pvss_params.g_1, Y) == E::pairing(A, ek)
            },
        );

        Ok(())
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

    let mut phi = DensePolynomial::<Fr>::rand(8192 / 3, rng);
    use ark_std::UniformRand;
    let domain = ark_poly::Radix2EvaluationDomain::<Fr>::new(8192)
        .ok_or_else(|| anyhow!("unable to construct domain"))
        .unwrap();

    let evals = phi.evaluate_over_domain_by_ref(domain);

    let g_1 = G1::prime_subgroup_generator();
    // commitment to coeffs
    let coeffs = fast_multiexp(&phi.coeffs, g_1.into_projective());

    use itertools::Itertools;

    let weight = 8192 / 150;
    let shares = (0..150)
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
