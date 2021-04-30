use super::nizkp;
use super::sh::Scalar;
use ark_bls12_381::G1Affine;
use ark_ec::AffineCurve;
use chacha20poly1305::aead::{generic_array::GenericArray, NewAead};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub type PublicKey = G1Affine;

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct AsymmetricPublicKey {
    #[serde(with = "crate::ark_serde")]
    pub enc: PublicKey,

    #[serde(with = "crate::ark_serde")]
    pub dec: PublicKey,
}

#[derive(Clone)]
pub struct AsymmetricKeypair {
    pub enc: Keypair, // Encrypt messages to recipient's enc
    pub dec: Keypair, // Decrypt messages with sender's dec
}

#[derive(Zeroize, Clone)]
#[zeroize(drop)]
pub struct Keypair {
    pub secret: Scalar,
    pub public: PublicKey,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SharedSecret {
    #[serde(with = "crate::ark_serde")]
    pub s: G1Affine,
}

impl SharedSecret {
    pub fn to_key(&self) -> [u8; 32] {
        use ark_ff::ToBytes;
        let mut params = blake2b_simd::Params::new();
        params.hash_length(32);
        let mut hasher = params.to_state();
        //hasher.write(b"Ferveo shared_secret_to_key"); //TODO personalization?
        self.s.write(&mut hasher);
        let mut key = [0u8; 32];
        key.copy_from_slice(hasher.finalize().as_bytes());
        key
    }
}

impl Keypair {
    pub fn base() -> G1Affine {
        G1Affine::prime_subgroup_generator() //TODO: hash to curve to get generator
    }
    pub fn new<R: rand::Rng + rand::RngCore + rand::CryptoRng>(
        rng: &mut R,
    ) -> Self {
        use ark_std::UniformRand;
        let secret = Scalar::rand(rng);
        Self {
            secret,
            public: Self::base().mul(secret).into(),
        }
    }
    pub fn nizkp<R: rand::Rng + rand::RngCore + rand::CryptoRng>(
        &self,
        other: &PublicKey,
        rng: &mut R,
    ) -> (SharedSecret, nizkp::NIZKP_BLS) {
        let shared_secret = self.shared_secret(&other);
        (
            shared_secret.clone(),
            nizkp::NIZKP_BLS::dleq(
                &Self::base(),
                &self.public,
                &other,
                &shared_secret.s,
                &self.secret,
                rng,
            ),
        )
    }
    pub fn shared_secret(&self, other: &PublicKey) -> SharedSecret {
        SharedSecret {
            s: other.mul(self.secret).into(),
        }
    }
}

impl AsymmetricKeypair {
    pub fn public(&self) -> AsymmetricPublicKey {
        AsymmetricPublicKey {
            enc: self.enc.public,
            dec: self.dec.public,
        }
    }
    pub fn base() -> G1Affine {
        Keypair::base()
    }
    pub fn new<R: rand::Rng + rand::RngCore + rand::CryptoRng>(
        rng: &mut R,
    ) -> Self {
        Self {
            enc: Keypair::new(rng),
            dec: Keypair::new(rng),
        }
    }
    pub fn encrypt_shared_secret(
        &self,
        decrypter: &AsymmetricPublicKey,
    ) -> SharedSecret {
        self.dec.shared_secret(&decrypter.enc).into()
    }

    pub fn decrypt_shared_secret(
        &self,
        encrypter: &AsymmetricPublicKey,
    ) -> SharedSecret {
        self.enc.shared_secret(&encrypter.dec).into()
    }

    // Get key to encrypt a message to send to decrypter
    pub fn encrypt_key(&self, decrypter: &AsymmetricPublicKey) -> [u8; 32] {
        self.encrypt_shared_secret(decrypter).to_key()
    }

    // Get key to decrypt a message received from encrypter
    pub fn decrypt_key(&self, encrypter: &AsymmetricPublicKey) -> [u8; 32] {
        self.decrypt_shared_secret(encrypter).to_key()
    }

    // Make a NIZKP of the shared secret, using the encrypter's private key
    pub fn encrypter_nizkp<R: rand::Rng + rand::RngCore + rand::CryptoRng>(
        &self,
        decrypter: &AsymmetricPublicKey,
        rng: &mut R,
    ) -> (SharedSecret, nizkp::NIZKP_BLS) {
        self.dec.nizkp(&decrypter.enc, rng)
    }

    // Make a NIZKP of the shared secret, using the decrypter's private key
    pub fn decrypter_nizkp<R: rand::Rng + rand::RngCore + rand::CryptoRng>(
        &self,
        encrypter: &AsymmetricPublicKey,
        rng: &mut R,
    ) -> (SharedSecret, nizkp::NIZKP_BLS) {
        self.enc.nizkp(&encrypter.dec, rng)
    }

    pub fn decrypt_cipher(
        &self,
        encrypter: &AsymmetricPublicKey,
    ) -> chacha20poly1305::XChaCha20Poly1305 {
        let shared_secret = self.decrypt_key(&encrypter);
        chacha20poly1305::XChaCha20Poly1305::new(&GenericArray::from_slice(
            &shared_secret,
        ))
    }

    pub fn encrypt_cipher(
        &self,
        decrypter: &AsymmetricPublicKey,
    ) -> chacha20poly1305::XChaCha20Poly1305 {
        let shared_secret = self.encrypt_key(&decrypter);
        chacha20poly1305::XChaCha20Poly1305::new(&GenericArray::from_slice(
            &shared_secret,
        ))
    }
}

impl AsymmetricPublicKey {
    // Verify a NIZKP created by the sender of an ecrypted message

    pub fn encrypter_nizkp_verify(
        encrypter: &AsymmetricPublicKey,
        decrypter: &AsymmetricPublicKey,
        shared_secret: &SharedSecret,
        nizkp: &nizkp::NIZKP_BLS,
    ) -> bool {
        nizkp.dleq_verify(
            &Keypair::base(),
            &encrypter.dec,
            &decrypter.enc,
            &shared_secret.s,
        )
    }

    // Verify a NIZKP created by the recipient of an ecrypted message\
    pub fn decrypter_nizkp_verify(
        encrypter: &AsymmetricPublicKey,
        decrypter: &AsymmetricPublicKey,
        shared_secret: &SharedSecret,
        nizkp: &nizkp::NIZKP_BLS,
    ) -> bool {
        nizkp.dleq_verify(
            &Keypair::base(),
            &encrypter.enc,
            &decrypter.dec,
            &shared_secret.s,
        )
    }
}
