use crate::*;
use chacha20::cipher::{NewCipher, StreamCipher};
use chacha20::{ChaCha20, Key, Nonce};

#[derive(Clone, Debug)]
pub struct Ciphertext<E: PairingEngine> {
    pub nonce: E::G1Affine,    // U
    pub ciphertext: Vec<u8>,   // V
    pub auth_tag: E::G2Affine, // W
}

impl<E: PairingEngine> Ciphertext<E> {
    pub fn check(&self, g_inv: &E::G1Prepared) -> bool {
        let hash_g2 = E::G2Prepared::from(self.construct_tag_hash());

        E::product_of_pairings(&[
            (E::G1Prepared::from(self.nonce), hash_g2),
            (g_inv.clone(), E::G2Prepared::from(self.auth_tag)),
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

pub fn encrypt<R: RngCore, E: PairingEngine>(
    message: &[u8],
    pubkey: E::G1Affine,
    rng: &mut R,
) -> Ciphertext<E> {
    let r = E::Fr::rand(rng);
    let g = E::G1Affine::prime_subgroup_generator();
    let h = E::G2Affine::prime_subgroup_generator();

    let ry_prep = E::G1Prepared::from(pubkey.mul(r).into());
    let s = E::product_of_pairings(&[(ry_prep, h.into())]);

    let u = g.mul(r).into();

    let mut cipher = shared_secret_to_chacha::<E>(&s);
    let mut v = message.to_vec();
    cipher.apply_keystream(&mut v);

    let w = construct_tag_hash::<E>(u, &v[..]).mul(r).into();

    Ciphertext::<E> {
        nonce: u,
        ciphertext: v,
        auth_tag: w,
    }
}

pub fn check_ciphertext_validity<E: PairingEngine>(c: &Ciphertext<E>) -> bool {
    let g_inv = E::G1Prepared::from(-E::G1Affine::prime_subgroup_generator());
    let hash_g2 = E::G2Prepared::from(construct_tag_hash::<E>(c.nonce, &c.ciphertext[..]));

    E::product_of_pairings(&[
        (E::G1Prepared::from(c.nonce), hash_g2),
        (g_inv, E::G2Prepared::from(c.auth_tag)),
    ]) == E::Fqk::one()
}

pub fn decrypt<E: PairingEngine>(ciphertext: &Ciphertext<E>, privkey: E::G2Affine) -> Vec<u8> {
    let s = E::product_of_pairings(&[(
        E::G1Prepared::from(ciphertext.nonce),
        E::G2Prepared::from(privkey),
    )]);
    decrypt_with_shared_secret(ciphertext, &s)
}
pub fn decrypt_with_shared_secret<E: PairingEngine>(
    ciphertext: &Ciphertext<E>,
    s: &E::Fqk,
) -> Vec<u8> {
    let mut plaintext = ciphertext.ciphertext.to_vec();
    let mut cipher = shared_secret_to_chacha::<E>(s);
    cipher.apply_keystream(&mut plaintext);

    plaintext
}

pub fn shared_secret_to_chacha<E: PairingEngine>(s: &E::Fqk) -> ChaCha20 {
    let mut prf_key = Vec::new();
    s.write(&mut prf_key).unwrap();
    let mut blake_params = blake2b_simd::Params::new();
    blake_params.hash_length(32);
    let mut hasher = blake_params.to_state();
    prf_key.write(&mut hasher).unwrap();
    let mut prf_key_32 = [0u8; 32];
    prf_key_32.clone_from_slice(hasher.finalize().as_bytes());
    let chacha_nonce = Nonce::from_slice(b"secret nonce");
    ChaCha20::new(Key::from_slice(&prf_key_32), chacha_nonce)
}
