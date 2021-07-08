use crate::*;
use chacha20poly1305::aead::{generic_array::GenericArray, Aead, NewAead};

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct AsymmetricPublicKey<Affine>
where
    Affine: AffineCurve,
{
    #[serde(with = "crate::ark_serde")]
    pub enc: Affine,

    #[serde(with = "crate::ark_serde")]
    pub dec: Affine,
}

#[derive(Clone)]
pub struct AsymmetricKeypair<Affine>
where
    Affine: AffineCurve,
{
    pub enc: Keypair<Affine>, // Encrypt messages to recipient's enc
    pub dec: Keypair<Affine>, // Decrypt messages with sender's dec
}

#[derive(Clone)]
//#[zeroize(drop)]
pub struct Keypair<Affine>
where
    Affine: AffineCurve,
{
    pub secret: Affine::ScalarField,
    pub public: Affine,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SharedSecret<Affine: AffineCurve> {
    #[serde(with = "crate::ark_serde")]
    pub s: Affine,
}

impl<Affine> SharedSecret<Affine>
where
    Affine: AffineCurve,
{
    pub fn to_key(&self) -> [u8; 32] {
        use ark_ff::ToBytes;
        let mut params = blake2b_simd::Params::new();
        params.hash_length(32);
        let mut hasher = params.to_state();
        //hasher.write(b"Ferveo shared_secret_to_key"); //TODO personalization?
        self.s.write(&mut hasher).unwrap();
        let mut key = [0u8; 32];
        key.copy_from_slice(hasher.finalize().as_bytes());
        key
    }
}

type PublicKey<Affine: AffineCurve> = Affine;

impl<Affine> Keypair<Affine>
where
    Affine: AffineCurve,
{
    pub fn base() -> Affine {
        Affine::prime_subgroup_generator() //TODO: hash to curve to get generator
    }
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        use ark_std::UniformRand;
        let secret = Affine::ScalarField::rand(rng);
        Self {
            secret,
            public: Self::base().mul(secret).into(),
        }
    }
    pub fn nizkp<R: Rng>(
        &self,
        other: &Affine,
        rng: &mut R,
    ) -> (SharedSecret<Affine>, NIZKP<Affine>) {
        let shared_secret = self.shared_secret(&other);
        (
            shared_secret.clone(),
            NIZKP::dleq(
                &Self::base(),
                &self.public,
                &other,
                &shared_secret.s,
                &self.secret,
                rng,
            ),
        )
    }
    pub fn shared_secret(
        &self,
        other: &PublicKey<Affine>,
    ) -> SharedSecret<Affine> {
        SharedSecret::<Affine> {
            s: other.mul(self.secret).into(),
        }
    }
}

impl<Affine> AsymmetricKeypair<Affine>
where
    Affine: AffineCurve,
{
    pub fn public(&self) -> AsymmetricPublicKey<Affine> {
        AsymmetricPublicKey {
            enc: self.enc.public,
            dec: self.dec.public,
        }
    }
    pub fn base() -> Affine {
        Keypair::base()
    }
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        Self {
            enc: Keypair::new(rng),
            dec: Keypair::new(rng),
        }
    }
    pub fn encrypt_shared_secret(
        &self,
        decrypter: &AsymmetricPublicKey<Affine>,
    ) -> SharedSecret<Affine> {
        self.dec.shared_secret(&decrypter.enc).into()
    }

    pub fn decrypt_shared_secret(
        &self,
        encrypter: &AsymmetricPublicKey<Affine>,
    ) -> SharedSecret<Affine> {
        self.enc.shared_secret(&encrypter.dec).into()
    }

    // Get key to encrypt a message to send to decrypter
    pub fn encrypt_key(
        &self,
        decrypter: &AsymmetricPublicKey<Affine>,
    ) -> [u8; 32] {
        self.encrypt_shared_secret(decrypter).to_key()
    }

    // Get key to decrypt a message received from encrypter
    pub fn decrypt_key(
        &self,
        encrypter: &AsymmetricPublicKey<Affine>,
    ) -> [u8; 32] {
        self.decrypt_shared_secret(encrypter).to_key()
    }

    // Make a NIZKP of the shared secret, using the encrypter's private key
    pub fn encrypter_nizkp<R: Rng>(
        &self,
        decrypter: &AsymmetricPublicKey<Affine>,
        rng: &mut R,
    ) -> (SharedSecret<Affine>, NIZKP<Affine>) {
        self.dec.nizkp(&decrypter.enc, rng)
    }

    // Make a NIZKP of the shared secret, using the decrypter's private key
    pub fn decrypter_nizkp<R: Rng>(
        &self,
        encrypter: &AsymmetricPublicKey<Affine>,
        rng: &mut R,
    ) -> (SharedSecret<Affine>, NIZKP<Affine>) {
        self.enc.nizkp(&encrypter.dec, rng)
    }

    pub fn decrypt_cipher(
        &self,
        encrypter: &AsymmetricPublicKey<Affine>,
    ) -> chacha20poly1305::XChaCha20Poly1305 {
        let shared_secret = self.decrypt_key(&encrypter);
        chacha20poly1305::XChaCha20Poly1305::new(&GenericArray::from_slice(
            &shared_secret,
        ))
    }

    pub fn encrypt_cipher(
        &self,
        decrypter: &AsymmetricPublicKey<Affine>,
    ) -> chacha20poly1305::XChaCha20Poly1305 {
        let shared_secret = self.encrypt_key(&decrypter);
        chacha20poly1305::XChaCha20Poly1305::new(&GenericArray::from_slice(
            &shared_secret,
        ))
    }
}

impl<Affine> AsymmetricPublicKey<Affine>
where
    Affine: AffineCurve,
{
    // Verify a NIZKP created by the sender of an encrypted message

    pub fn encrypter_nizkp_verify(
        encrypter: &Self,
        decrypter: &Self,
        shared_secret: &SharedSecret<Affine>,
        nizkp: &NIZKP<Affine>,
    ) -> bool {
        nizkp.dleq_verify(
            &Keypair::base(),
            &encrypter.dec,
            &decrypter.enc,
            &shared_secret.s,
        )
    }

    // Verify a NIZKP created by the recipient of an encrypted message
    pub fn decrypter_nizkp_verify(
        encrypter: &Self,
        decrypter: &Self,
        shared_secret: &SharedSecret<Affine>,
        nizkp: &NIZKP<Affine>,
    ) -> bool {
        nizkp.dleq_verify(
            &Keypair::base(),
            &encrypter.enc,
            &decrypter.dec,
            &shared_secret.s,
        )
    }
}

use ark_ec::PairingEngine;

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct PubliclyVerifiablePublicKey<E>
where
    E: PairingEngine,
{
    #[serde(with = "crate::ark_serde")]
    pub encryption_key: E::G2Affine,

    #[serde(with = "crate::ark_serde")]
    pub verification_key: E::G1Affine,
}

#[derive(Clone)]
pub struct PubliclyVerifiableKeypair<E>
where
    E: PairingEngine,
{
    pub decryption_key: E::Fr,
    pub signing_key: E::Fr,
}

impl<E> PubliclyVerifiableKeypair<E>
where
    E: PairingEngine,
{
    pub fn public(&self) -> PubliclyVerifiablePublicKey<E> {
        PubliclyVerifiablePublicKey::<E> {
            encryption_key: E::G2Affine::prime_subgroup_generator()
                .mul(self.decryption_key)
                .into_affine(),
            verification_key: E::G1Affine::prime_subgroup_generator()
                .mul(self.signing_key)
                .into_affine(),
        }
    }

    pub fn new<R: Rng>(rng: &mut R) -> Self {
        use ark_std::UniformRand;
        Self {
            decryption_key: E::Fr::rand(rng),
            signing_key: E::Fr::rand(rng),
        }
    }
}
