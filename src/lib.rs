use std::num::NonZeroU32;

use argon2::{Algorithm, Argon2, Params, Version};
use pqcrypto_mldsa::mldsa87;
use pqcrypto_mlkem::mlkem1024;
use pqcrypto_traits::kem::{
    Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _,
};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use rand::{RngCore, rngs::OsRng};
use ring::{aead, hkdf, pbkdf2};
use rsa::pkcs8::LineEnding;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::{Oaep, Pss, RsaPrivateKey, RsaPublicKey, sha2::Digest, sha2::Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const SALT_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;
const HASH_LENGTH: usize = 32;
const PBKDF2_ITERATIONS: NonZeroU32 = NonZeroU32::new(600_000).unwrap();
const ARGON2_MEMORY_KIB: u32 = 19_456;
const ARGON2_ITERATIONS: u32 = 2;
const PASSWORD_LENGTH: std::ops::RangeInclusive<usize> = 8..=1024;
const SECRET_LENGTH: std::ops::RangeInclusive<usize> = 16..=1024;
const RSA_BITS: usize = 4096;
const HKDF_INFO: &[&[u8]] = &[b"cryptolib"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidInput,
    InvalidKey,
    MissingKey,
    Encryption,
    Decryption,
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        let message = match self {
            Self::InvalidInput => "invalid input",
            Self::InvalidKey => "invalid key",
            Self::MissingKey => "key not set",
            Self::Encryption => "encryption failed",
            Self::Decryption => "decryption failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

fn random_bytes<const LENGTH: usize>() -> [u8; LENGTH] {
    let mut bytes = [0u8; LENGTH];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn aes_key(key_bytes: &[u8]) -> aead::LessSafeKey {
    let unbound =
        aead::UnboundKey::new(&aead::AES_256_GCM, key_bytes).expect("32-byte key");
    aead::LessSafeKey::new(unbound)
}

fn hkdf_key(secret: &[u8], salt: &[u8]) -> aead::LessSafeKey {
    let pseudo_random_key = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(secret);
    let output = pseudo_random_key
        .expand(HKDF_INFO, &aead::AES_256_GCM)
        .expect("valid HKDF length");
    aead::LessSafeKey::new(aead::UnboundKey::from(output))
}

fn seal(key: &aead::LessSafeKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce = random_bytes::<NONCE_LENGTH>();
    let mut buffer = plaintext.to_vec();
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::empty(),
        &mut buffer,
    )
    .map_err(|_| Error::Encryption)?;
    Ok([nonce.as_slice(), &buffer].concat())
}

fn open(key: &aead::LessSafeKey, sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < NONCE_LENGTH + TAG_LENGTH {
        return Err(Error::InvalidInput);
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LENGTH);
    let nonce =
        aead::Nonce::try_assume_unique_for_key(nonce).map_err(|_| Error::InvalidInput)?;
    let mut buffer = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(nonce, aead::Aad::empty(), &mut buffer)
        .map_err(|_| Error::Decryption)?;
    Ok(plaintext.to_vec())
}

fn split_salt(data: &[u8], minimum_rest: usize) -> Result<(&[u8], &[u8])> {
    if data.len() < SALT_LENGTH + minimum_rest {
        return Err(Error::InvalidInput);
    }
    Ok(data.split_at(SALT_LENGTH))
}

fn validate_password(password: &[u8]) -> Result<()> {
    if !PASSWORD_LENGTH.contains(&password.len()) {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

pub struct SecureAES {
    secret: Zeroizing<Vec<u8>>,
}

impl SecureAES {
    pub fn new(secret: &[u8]) -> Result<Self> {
        if !SECRET_LENGTH.contains(&secret.len()) {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            secret: Zeroizing::new(secret.to_vec()),
        })
    }

    fn derive_key(&self, salt: &[u8]) -> aead::LessSafeKey {
        let mut key_bytes = Zeroizing::new([0u8; 32]);
        let algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
        pbkdf2::derive(
            algorithm,
            PBKDF2_ITERATIONS,
            salt,
            &self.secret,
            &mut *key_bytes,
        );
        aes_key(&*key_bytes)
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let salt = random_bytes::<SALT_LENGTH>();
        let sealed = seal(&self.derive_key(&salt), plaintext)?;
        Ok([salt.as_slice(), &sealed].concat())
    }

    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        let (salt, sealed) = split_salt(encrypted, NONCE_LENGTH + TAG_LENGTH)?;
        open(&self.derive_key(salt), sealed)
    }
}

pub struct SecureArgon2id {
    argon2: Argon2<'static>,
}

impl Default for SecureArgon2id {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureArgon2id {
    pub fn new() -> Self {
        let params =
            Params::new(ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, 1, Some(HASH_LENGTH))
                .expect("valid Argon2 parameters");
        Self {
            argon2: Argon2::new(Algorithm::Argon2id, Version::V0x13, params),
        }
    }

    fn hash(&self, password: &[u8], salt: &[u8]) -> Result<[u8; HASH_LENGTH]> {
        validate_password(password)?;
        let mut hash = [0u8; HASH_LENGTH];
        self.argon2
            .hash_password_into(password, salt, &mut hash)
            .map_err(|_| Error::InvalidInput)?;
        Ok(hash)
    }

    pub fn hash_password(&self, password: &[u8]) -> Result<Vec<u8>> {
        let salt = random_bytes::<SALT_LENGTH>();
        Ok([self.hash(password, &salt)?.as_slice(), &salt].concat())
    }

    pub fn verify_password(&self, password: &[u8], stored: &[u8]) -> Result<bool> {
        if stored.len() != HASH_LENGTH + SALT_LENGTH {
            return Err(Error::InvalidInput);
        }
        let (expected, salt) = stored.split_at(HASH_LENGTH);
        Ok(self.hash(password, salt)?.ct_eq(expected).into())
    }
}

#[derive(Default)]
pub struct SecurePbkdf2;

impl SecurePbkdf2 {
    pub fn new() -> Self {
        Self
    }

    pub fn hash_password(&self, password: &[u8]) -> Result<Vec<u8>> {
        validate_password(password)?;
        let salt = random_bytes::<SALT_LENGTH>();
        let mut hash = [0u8; HASH_LENGTH];
        let algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
        pbkdf2::derive(algorithm, PBKDF2_ITERATIONS, &salt, password, &mut hash);
        Ok([hash.as_slice(), &salt].concat())
    }

    pub fn verify_password(&self, password: &[u8], stored: &[u8]) -> Result<bool> {
        validate_password(password)?;
        if stored.len() != HASH_LENGTH + SALT_LENGTH {
            return Err(Error::InvalidInput);
        }
        let (expected, salt) = stored.split_at(HASH_LENGTH);
        let algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
        Ok(
            pbkdf2::verify(algorithm, PBKDF2_ITERATIONS, salt, password, expected)
                .is_ok(),
        )
    }
}

#[derive(Default)]
pub struct SecureRSA {
    private_key: Option<RsaPrivateKey>,
    public_key: Option<RsaPublicKey>,
}

impl SecureRSA {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn generate_keypair(&mut self) -> Result<(Zeroizing<String>, String)> {
        let private_key =
            RsaPrivateKey::new(&mut OsRng, RSA_BITS).map_err(|_| Error::InvalidKey)?;
        self.set_private(private_key);
        let private_pem = self.private_key()?.to_pkcs8_pem(LineEnding::LF);
        let public_pem = self.public_key()?.to_public_key_pem(LineEnding::LF);
        match (private_pem, public_pem) {
            (Ok(private_pem), Ok(public_pem)) => Ok((private_pem, public_pem)),
            _ => Err(Error::InvalidKey),
        }
    }

    fn set_private(&mut self, private_key: RsaPrivateKey) {
        self.public_key = Some(private_key.to_public_key());
        self.private_key = Some(private_key);
    }

    pub fn set_private_key(&mut self, private_key_pem: &str) -> Result<()> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
            .map_err(|_| Error::InvalidKey)?;
        self.set_private(private_key);
        Ok(())
    }

    pub fn set_public_key(&mut self, public_key_pem: &str) -> Result<()> {
        let public_key = RsaPublicKey::from_public_key_pem(public_key_pem)
            .map_err(|_| Error::InvalidKey)?;
        self.public_key = Some(public_key);
        Ok(())
    }

    fn private_key(&self) -> Result<&RsaPrivateKey> {
        self.private_key.as_ref().ok_or(Error::MissingKey)
    }

    fn public_key(&self) -> Result<&RsaPublicKey> {
        self.public_key.as_ref().ok_or(Error::MissingKey)
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let key_bytes = Zeroizing::new(random_bytes::<32>());
        let wrapped_key = self
            .public_key()?
            .encrypt(&mut OsRng, Oaep::new::<Sha256>(), &*key_bytes)
            .map_err(|_| Error::Encryption)?;
        let sealed = seal(&aes_key(&*key_bytes), plaintext)?;
        let length = (wrapped_key.len() as u32).to_be_bytes();
        Ok([length.as_slice(), &wrapped_key, &sealed].concat())
    }

    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        let (length, rest) = encrypted.split_at_checked(4).ok_or(Error::InvalidInput)?;
        let length = u32::from_be_bytes(length.try_into().unwrap()) as usize;
        let (wrapped_key, sealed) =
            rest.split_at_checked(length).ok_or(Error::InvalidInput)?;
        let key_bytes = Zeroizing::new(
            self.private_key()?
                .decrypt(Oaep::new::<Sha256>(), wrapped_key)
                .map_err(|_| Error::Decryption)?,
        );
        if key_bytes.len() != 32 {
            return Err(Error::Decryption);
        }
        open(&aes_key(&key_bytes), sealed)
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let digest = Sha256::digest(data);
        self.private_key()?
            .sign_with_rng(&mut OsRng, Pss::new::<Sha256>(), &digest)
            .map_err(|_| Error::InvalidKey)
    }

    pub fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        let digest = Sha256::digest(data);
        let verified =
            self.public_key()?
                .verify(Pss::new::<Sha256>(), &digest, signature);
        Ok(verified.is_ok())
    }
}

#[derive(Default)]
pub struct SecureMlKem {
    secret_key: Option<mlkem1024::SecretKey>,
    public_key: Option<mlkem1024::PublicKey>,
}

impl SecureMlKem {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn generate_keypair(&mut self) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
        let (public_key, secret_key) = mlkem1024::keypair();
        let exported = (
            Zeroizing::new(secret_key.as_bytes().to_vec()),
            public_key.as_bytes().to_vec(),
        );
        self.secret_key = Some(secret_key);
        self.public_key = Some(public_key);
        exported
    }

    pub fn from_public_key(public_key: &[u8]) -> Result<Self> {
        let public_key = mlkem1024::PublicKey::from_bytes(public_key)
            .map_err(|_| Error::InvalidKey)?;
        Ok(Self {
            secret_key: None,
            public_key: Some(public_key),
        })
    }

    pub fn set_private_key(&mut self, secret_key: &[u8]) -> Result<()> {
        let secret_key = mlkem1024::SecretKey::from_bytes(secret_key)
            .map_err(|_| Error::InvalidKey)?;
        self.secret_key = Some(secret_key);
        Ok(())
    }

    pub fn encapsulate(&self) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
        let public_key = self.public_key.as_ref().ok_or(Error::MissingKey)?;
        let (shared_secret, ciphertext) = mlkem1024::encapsulate(public_key);
        Ok((
            ciphertext.as_bytes().to_vec(),
            Zeroizing::new(shared_secret.as_bytes().to_vec()),
        ))
    }

    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let secret_key = self.secret_key.as_ref().ok_or(Error::MissingKey)?;
        let ciphertext = mlkem1024::Ciphertext::from_bytes(ciphertext)
            .map_err(|_| Error::InvalidInput)?;
        let shared_secret = mlkem1024::decapsulate(&ciphertext, secret_key);
        Ok(Zeroizing::new(shared_secret.as_bytes().to_vec()))
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let (ciphertext, shared_secret) = self.encapsulate()?;
        let salt = random_bytes::<SALT_LENGTH>();
        let sealed = seal(&hkdf_key(&shared_secret, &salt), plaintext)?;
        Ok([salt.as_slice(), &ciphertext, &sealed].concat())
    }

    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        let ciphertext_length = mlkem1024::ciphertext_bytes();
        let (salt, rest) = split_salt(encrypted, ciphertext_length)?;
        let (ciphertext, sealed) = rest.split_at(ciphertext_length);
        let shared_secret = self.decapsulate(ciphertext)?;
        open(&hkdf_key(&shared_secret, salt), sealed)
    }
}

#[derive(Default)]
pub struct SecureMlDsa {
    secret_key: Option<mldsa87::SecretKey>,
    public_key: Option<mldsa87::PublicKey>,
}

impl SecureMlDsa {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn generate_keypair(&mut self) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
        let (public_key, secret_key) = mldsa87::keypair();
        let exported = (
            Zeroizing::new(secret_key.as_bytes().to_vec()),
            public_key.as_bytes().to_vec(),
        );
        self.secret_key = Some(secret_key);
        self.public_key = Some(public_key);
        exported
    }

    pub fn set_private_key(&mut self, secret_key: &[u8]) -> Result<()> {
        let secret_key =
            mldsa87::SecretKey::from_bytes(secret_key).map_err(|_| Error::InvalidKey)?;
        self.secret_key = Some(secret_key);
        Ok(())
    }

    pub fn set_public_key(&mut self, public_key: &[u8]) -> Result<()> {
        let public_key =
            mldsa87::PublicKey::from_bytes(public_key).map_err(|_| Error::InvalidKey)?;
        self.public_key = Some(public_key);
        Ok(())
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let secret_key = self.secret_key.as_ref().ok_or(Error::MissingKey)?;
        Ok(mldsa87::detached_sign(data, secret_key).as_bytes().to_vec())
    }

    pub fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        let public_key = self.public_key.as_ref().ok_or(Error::MissingKey)?;
        let Ok(signature) = mldsa87::DetachedSignature::from_bytes(signature) else {
            return Ok(false);
        };
        Ok(mldsa87::verify_detached_signature(&signature, data, public_key).is_ok())
    }
}
