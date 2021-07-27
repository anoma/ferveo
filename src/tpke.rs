use crate::*;
use ark_ec::PairingEngine;

#[derive(Clone, Debug)]
pub struct Ciphertext<E: PairingEngine> {
    pub nonce: E::G1Affine,    // U
    pub ciphertext: Vec<u8>,   // V
    pub auth_tag: E::G2Affine, // W
}

impl<E> Ciphertext<E>
where
    E: PairingEngine,
{
    pub fn check(&self, g_inv: &E::G1Prepared) -> bool {
        let hash_g2 = E::G2Prepared::from(self.construct_tag_hash());

        E::product_of_pairings(&[
            (E::G1Prepared::from(self.nonce), hash_g2),
            (*g_inv, E::G2Prepared::from(self.auth_tag)),
        ]) == E::Fqk::one()
    }
    fn construct_tag_hash(&self) -> E::G2Affine {
        use ark_ff::ToBytes;
        let mut hash_input = Vec::<u8>::new();
        self.nonce.write(&mut hash_input).unwrap();
        hash_input.extend_from_slice(&self.ciphertext);

        hash_to_g2(&hash_input)
    }
}

pub struct BlindedKeyShare<E: PairingEngine> {
    pub window_table: Vec<Vec<E::G2Affine>>,
}

#[derive(Clone, Debug)]
pub struct DecryptionShare<E: PairingEngine>(pub E::G1Affine);

pub struct ValidatorPublicKey<E: PairingEngine> {
    pub blinding_public_key: E::G2Prepared,
    pub domain: Vec<E::Fr>,
    pub blinded_key_shares: Vec<BlindedKeyShare<E>>,
    pub public_key_shares: Vec<E::G1Affine>,
}

pub struct DecryptionContext<E: PairingEngine> {
    pub validators: ValidatorPublicKey<E>,
}

pub struct ValidatorPrivateKey<E: PairingEngine> {
    pub b: E::Fr,
    pub domain: Vec<E::Fr>,
    pub key_shares: Vec<E::G2Affine>,
}

pub fn setup<E: PairingEngine>(
    threshold: usize,
    shares_num: usize,
) -> (E::G1Affine, E::G2Affine, Vec<PrivkeyShare<P>>) {
    let rng = &mut ark_std::test_rng();
    let g = E::G1Affine::prime_subgroup_generator();
    let h = E::G2Affine::prime_subgroup_generator();

    assert!(shares_num >= threshold);
    let threshold_poly = DensePolynomial::<E::Fr>::rand(threshold - 1, rng);
    let mut pubkey_shares: Vec<E::G1Affine> = vec![];
    let mut privkey_shares = vec![];

    for i in 1..=shares_num {
        let pt = <E::Fr as From<u64>>::from(i as u64);
        let privkey_coeff = threshold_poly.evaluate(&pt);

        pubkey_shares.push(g.mul(privkey_coeff).into());

        let privkey = PrivkeyShare::<P> {
            index: i,
            privkey: h.mul(privkey_coeff).into(),
            pubkey: pubkey_shares[i - 1],
        };
        privkey_shares.push(privkey);
    }

    let z = E::Fr::zero();
    let x = threshold_poly.evaluate(&z);
    let pubkey = g.mul(x);
    let privkey = h.mul(x);

    (pubkey.into(), privkey.into(), privkey_shares)
}
