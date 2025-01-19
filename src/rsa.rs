use libc::{c_void, madvise, mlock, munlock, MADV_DONTDUMP};
use rand::{rngs::OsRng, RngCore};
use ring::{aead, constant_time, pbkdf2};
use rsa::{
    pkcs1::{
        DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey,
        LineEnding,
    },
    pss::{BlindedSigningKey, Signature, VerifyingKey},
    signature::{RandomizedSigner, SignatureEncoding, Verifier},
    traits::PublicKeyParts,
    Oaep, RsaPrivateKey, RsaPublicKey,
};
use std::{num::NonZeroU32, ptr};

// OWASP recommended parameters
// https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#algorithms
const RSA_BITS: usize = 4096;
const MIN_RSA_BITS: usize = 2048;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const PBKDF2_ITERATIONS: u32 = 100_000;

#[derive(Debug)]
pub enum RSAError {
    KeyGenerationError,
    EncryptionError,
    DecryptionError,
    SigningError,
    VerificationError,
    InvalidKey,
    InvalidData,
    MemoryLockError,
    ValidationError,
}

/// A secure RSA implementation with memory protection and constant-time operations.
pub struct SecureRSA {
    public_key: Option<RsaPublicKey>,
    private_key: Option<RsaPrivateKey>,
    memory_locked: bool,
}

impl SecureRSA {
    /// Creates a new RSA instance for encryption and signing.
    pub fn new() -> Self {
        Self {
            public_key: None,
            private_key: None,
            memory_locked: false,
        }
    }

    fn secure_zero(buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            unsafe { ptr::write_volatile(byte, 0) };
        }
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    }

    fn protect_buffer(buf: &mut [u8]) -> Result<(), RSAError> {
        let ptr = buf.as_ptr() as *const c_void;
        let size = buf.len();

        unsafe {
            mlock(ptr, size);
            madvise(ptr as *mut c_void, size, MADV_DONTDUMP);
        }
        Ok(())
    }

    fn unprotect_buffer(buf: &mut [u8]) -> Result<(), RSAError> {
        let ptr = buf.as_ptr() as *const c_void;
        let size = buf.len();
        unsafe { munlock(ptr, size) };
        Self::secure_zero(buf);
        Ok(())
    }

    fn lock_memory(&mut self) -> Result<(), RSAError> {
        if self.memory_locked {
            return Ok(());
        }

        if let Some(ref private_key) = self.private_key {
            let ptr = private_key as *const _ as *const c_void;
            let size = std::mem::size_of_val(private_key);

            unsafe {
                mlock(ptr, size);
                madvise(ptr as *mut c_void, size, MADV_DONTDUMP);
            }
            self.memory_locked = true;
        }
        Ok(())
    }

    fn unlock_memory(&mut self) -> Result<(), RSAError> {
        if !self.memory_locked {
            return Ok(());
        }

        if let Some(ref private_key) = self.private_key {
            let ptr = private_key as *const _ as *const c_void;
            let size = std::mem::size_of_val(private_key);
            unsafe { munlock(ptr, size) };
        }
        self.memory_locked = false;
        Ok(())
    }

    fn validate_key_size(key_size: usize) -> Result<(), RSAError> {
        if key_size * 8 < MIN_RSA_BITS {
            return Err(RSAError::ValidationError);
        }
        Ok(())
    }

    /// Generates a new RSA key pair (minimum 2048 bits).
    ///
    /// # Returns
    /// * `Result<(Vec<u8>, Vec<u8>), RSAError>` - (private_key_pem, public_key_pem) or an error
    pub fn generate_keypair(&mut self) -> Result<(Vec<u8>, Vec<u8>), RSAError> {
        self.unlock_memory().ok();

        let mut rng = OsRng;
        let private_key =
            RsaPrivateKey::new(&mut rng, RSA_BITS).map_err(|_| RSAError::KeyGenerationError)?;

        Self::validate_key_size(private_key.size())?;

        let public_key = RsaPublicKey::from(&private_key);

        let mut private_key_pem = private_key
            .to_pkcs1_pem(LineEnding::LF)
            .map_err(|_| RSAError::KeyGenerationError)?
            .as_bytes()
            .to_vec();
        Self::protect_buffer(&mut private_key_pem)?;

        let public_key_pem = public_key
            .to_pkcs1_pem(LineEnding::LF)
            .map_err(|_| RSAError::KeyGenerationError)?
            .as_bytes()
            .to_vec();

        self.private_key = Some(private_key);
        self.public_key = Some(public_key);

        self.lock_memory()?;

        let result = (private_key_pem.clone(), public_key_pem);
        Self::unprotect_buffer(&mut private_key_pem)?;

        Ok(result)
    }

    fn derive_key(secret: &[u8], salt: &[u8]) -> Result<aead::LessSafeKey, RSAError> {
        let mut key_bytes = [0u8; KEY_LEN];

        Self::protect_buffer(&mut key_bytes)?;

        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
            salt,
            secret,
            &mut key_bytes,
        );

        let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes)
            .map_err(|_| RSAError::EncryptionError)?;

        Self::unprotect_buffer(&mut key_bytes)?;

        Ok(aead::LessSafeKey::new(unbound_key))
    }

    /// Encrypts data using RSA-OAEP with SHA-256.
    ///
    /// # Arguments
    /// * `plaintext` - The data to encrypt
    ///
    /// # Returns
    /// * `Result<Vec<u8>, RSAError>` - The encrypted data or an error
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, RSAError> {
        let public_key = self.public_key.as_ref().ok_or(RSAError::InvalidKey)?;

        Self::validate_key_size(public_key.size())?;

        let mut rng = OsRng;

        let mut aes_key = vec![0u8; KEY_LEN];
        Self::protect_buffer(&mut aes_key)?;
        rng.fill_bytes(&mut aes_key);

        let mut salt = [0u8; SALT_LEN];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        Self::protect_buffer(&mut salt)?;
        Self::protect_buffer(&mut nonce_bytes)?;
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce_bytes);

        let key = Self::derive_key(&aes_key, &salt)?;

        let mut in_out = plaintext.to_vec();
        Self::protect_buffer(&mut in_out)?;

        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
        key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
            .map_err(|_| RSAError::EncryptionError)?;

        let padding = Oaep::new::<sha2::Sha256>();
        let encrypted_aes_key = public_key
            .encrypt(&mut rng, padding, &aes_key)
            .map_err(|_| RSAError::EncryptionError)?;

        let mut result =
            Vec::with_capacity(4 + encrypted_aes_key.len() + SALT_LEN + NONCE_LEN + in_out.len());
        result.extend_from_slice(&(encrypted_aes_key.len() as u32).to_be_bytes());
        result.extend_from_slice(&encrypted_aes_key);
        result.extend_from_slice(&salt);
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&in_out);

        Self::unprotect_buffer(&mut aes_key)?;
        Self::unprotect_buffer(&mut salt)?;
        Self::unprotect_buffer(&mut nonce_bytes)?;
        Self::unprotect_buffer(&mut in_out)?;

        Ok(result)
    }

    /// Decrypts RSA-OAEP encrypted data.
    ///
    /// # Arguments
    /// * `ciphertext` - The encrypted data
    ///
    /// # Returns
    /// * `Result<Vec<u8>, RSAError>` - The decrypted data or an error
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, RSAError> {
        let private_key = self.private_key.as_ref().ok_or(RSAError::InvalidKey)?;

        Self::validate_key_size(private_key.size())?;

        if ciphertext.len() < 4 + SALT_LEN + NONCE_LEN {
            return Err(RSAError::InvalidData);
        }

        let key_len = u32::from_be_bytes(
            ciphertext[..4]
                .try_into()
                .map_err(|_| RSAError::InvalidData)?,
        ) as usize;
        if ciphertext.len() < 4 + key_len + SALT_LEN + NONCE_LEN {
            return Err(RSAError::InvalidData);
        }

        let encrypted_aes_key = &ciphertext[4..4 + key_len];
        let salt = &ciphertext[4 + key_len..4 + key_len + SALT_LEN];
        let nonce_bytes = &ciphertext[4 + key_len + SALT_LEN..4 + key_len + SALT_LEN + NONCE_LEN];
        let encrypted_data = &ciphertext[4 + key_len + SALT_LEN + NONCE_LEN..];

        let padding = Oaep::new::<sha2::Sha256>();

        let mut aes_key = private_key
            .decrypt(padding, encrypted_aes_key)
            .map_err(|_| RSAError::DecryptionError)?;
        Self::protect_buffer(&mut aes_key)?;

        let key = Self::derive_key(&aes_key, salt)?;

        let mut decrypted_data = encrypted_data.to_vec();
        Self::protect_buffer(&mut decrypted_data)?;

        let nonce = aead::Nonce::assume_unique_for_key(
            nonce_bytes
                .try_into()
                .map_err(|_| RSAError::DecryptionError)?,
        );

        let decrypted_len = key
            .open_in_place(nonce, aead::Aad::empty(), &mut decrypted_data)
            .map_err(|_| RSAError::DecryptionError)?
            .len();

        decrypted_data.truncate(decrypted_len);

        let result = decrypted_data.clone();
        Self::unprotect_buffer(&mut aes_key)?;
        Self::unprotect_buffer(&mut decrypted_data)?;

        Ok(result)
    }

    /// Signs data using RSA-PSS with SHA-256.
    ///
    /// # Arguments
    /// * `data` - The data to sign
    ///
    /// # Returns
    /// * `Result<Vec<u8>, RSAError>` - The signature or an error
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RSAError> {
        let private_key = self.private_key.as_ref().ok_or(RSAError::InvalidKey)?;

        Self::validate_key_size(private_key.size())?;

        let mut rng = OsRng;

        let signing_key = BlindedSigningKey::<sha2::Sha256>::new(private_key.clone());
        signing_key
            .try_sign_with_rng(&mut rng, data)
            .map(|sig| sig.to_vec())
            .map_err(|_| RSAError::SigningError)
    }

    /// Verifies an RSA-PSS signature.
    ///
    /// # Arguments
    /// * `data` - The original data
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    /// * `Result<bool, RSAError>` - True if signature is valid
    pub fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, RSAError> {
        let public_key = self.public_key.as_ref().ok_or(RSAError::InvalidKey)?;

        Self::validate_key_size(public_key.size())?;

        let verifying_key = VerifyingKey::<sha2::Sha256>::new(public_key.clone());
        let sig = Signature::try_from(signature).map_err(|_| RSAError::VerificationError)?;

        Ok(constant_time::verify_slices_are_equal(
            &verifying_key
                .verify(data, &sig)
                .ok()
                .map(|_| [1u8])
                .unwrap_or([0u8]),
            &[1u8],
        )
        .is_ok())
    }

    /// Clears all sensitive data from memory.
    pub fn clear_sensitive_data(&mut self) {
        self.unlock_memory().ok();

        if let Some(ref mut private_key) = self.private_key {
            let ptr = private_key as *mut _ as *mut u8;
            let size = std::mem::size_of_val(&private_key);
            unsafe {
                for i in 0..size {
                    ptr::write_volatile(ptr.add(i), 0);
                }
            }
        }

        self.private_key = None;
        self.public_key = None;
        self.memory_locked = false;

        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    }

    /// Generates a public key from an existing private key.
    ///
    /// # Arguments
    /// * `private_key_pem` - The PEM-encoded private key
    ///
    /// # Returns
    /// * `Result<Vec<u8>, RSAError>` - The public key in PEM format
    pub fn generate_public_key(&mut self, private_key_pem: &[u8]) -> Result<Vec<u8>, RSAError> {
        let private_key = RsaPrivateKey::from_pkcs1_pem(
            std::str::from_utf8(private_key_pem).map_err(|_| RSAError::InvalidKey)?,
        )
        .map_err(|_| RSAError::InvalidKey)?;

        Self::validate_key_size(private_key.size())?;

        let public_key = RsaPublicKey::from(&private_key);

        let public_key_pem = public_key
            .to_pkcs1_pem(LineEnding::LF)
            .map_err(|_| RSAError::KeyGenerationError)?
            .as_bytes()
            .to_vec();

        self.public_key = Some(public_key);
        Ok(public_key_pem)
    }

    /// Sets the public key for encryption and verification.
    ///
    /// # Arguments
    /// * `public_key_pem` - The PEM-encoded public key
    ///
    /// # Returns
    /// * `Result<(), RSAError>` - Success or an error
    pub fn set_public_key(&mut self, public_key_pem: &[u8]) -> Result<(), RSAError> {
        let public_key = RsaPublicKey::from_pkcs1_pem(
            std::str::from_utf8(public_key_pem).map_err(|_| RSAError::InvalidKey)?,
        )
        .map_err(|_| RSAError::InvalidKey)?;

        Self::validate_key_size(public_key.size())?;

        self.public_key = Some(public_key);
        Ok(())
    }

    /// Sets the private key for decryption and signing.
    ///
    /// # Arguments
    /// * `private_key_pem` - The PEM-encoded private key
    ///
    /// # Returns
    /// * `Result<(), RSAError>` - Success or an error
    pub fn set_private_key(&mut self, private_key_pem: &[u8]) -> Result<(), RSAError> {
        self.unlock_memory().ok();

        let private_key = RsaPrivateKey::from_pkcs1_pem(
            std::str::from_utf8(private_key_pem).map_err(|_| RSAError::InvalidKey)?,
        )
        .map_err(|_| RSAError::InvalidKey)?;

        Self::validate_key_size(private_key.size())?;

        let public_key = RsaPublicKey::from(&private_key);

        self.private_key = Some(private_key);
        self.public_key = Some(public_key);

        self.lock_memory()?;

        Ok(())
    }
}

impl Drop for SecureRSA {
    fn drop(&mut self) {
        self.clear_sensitive_data();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn test_key_generation() {
        let mut rsa = SecureRSA::new();
        let (private_key, public_key) = rsa.generate_keypair().unwrap();
        assert!(!private_key.is_empty(), "Generated private key is empty");
        assert!(!public_key.is_empty(), "Generated public key is empty");
    }

    #[test]
    fn test_public_key_from_private() {
        let mut rsa = SecureRSA::new();
        let (private_key, original_public_key) = rsa.generate_keypair().unwrap();

        let mut rsa2 = SecureRSA::new();
        let generated_public_key = rsa2.generate_public_key(&private_key).unwrap();

        assert_eq!(
            original_public_key, generated_public_key,
            "Generated public key does not match the original public key"
        );
    }

    #[test]
    fn test_encryption_decryption() {
        let mut rsa = SecureRSA::new();
        rsa.generate_keypair().unwrap();

        let plaintext = b"Lorem ipsum dolor sit amet";
        let encrypted = rsa.encrypt(plaintext).unwrap();
        let decrypted = rsa.decrypt(&encrypted).unwrap();

        assert_eq!(
            plaintext.to_vec(),
            decrypted,
            "Decrypted text does not match original plaintext"
        );
    }

    #[test]
    fn test_encryption_with_public_key_only() {
        let mut rsa = SecureRSA::new();
        let (_, public_key) = rsa.generate_keypair().unwrap();

        let mut public_only_rsa = SecureRSA::new();
        public_only_rsa.set_public_key(&public_key).unwrap();

        let plaintext = b"Lorem ipsum dolor sit amet";
        let encrypted = public_only_rsa.encrypt(plaintext).unwrap();

        assert!(
            public_only_rsa.decrypt(&encrypted).is_err(),
            "Decryption should fail with public key only"
        );
    }

    #[test]
    fn test_signing_verification() {
        let mut rsa = SecureRSA::new();
        let (_, public_key) = rsa.generate_keypair().unwrap();

        let data = b"Lorem ipsum dolor sit amet";
        let signature = rsa.sign(data).unwrap();

        assert!(
            rsa.verify_signature(data, &signature).unwrap(),
            "Signature verification failed with original key pair"
        );

        let mut public_only_rsa = SecureRSA::new();
        public_only_rsa.set_public_key(&public_key).unwrap();
        assert!(
            public_only_rsa.verify_signature(data, &signature).unwrap(),
            "Signature verification failed with public key only"
        );

        let modified_data = b"Lorem ipsum dolor sit amet consectetur";
        assert!(
            !rsa.verify_signature(modified_data, &signature).unwrap(),
            "Signature verification should fail with modified data"
        );
    }

    #[test]
    fn test_different_ciphertexts() {
        let mut rsa = SecureRSA::new();
        rsa.generate_keypair().unwrap();

        let plaintext = b"Lorem ipsum dolor sit amet";
        let encrypted1 = rsa.encrypt(plaintext).unwrap();
        let encrypted2 = rsa.encrypt(plaintext).unwrap();

        assert_ne!(
            encrypted1, encrypted2,
            "Encrypted results should be different due to padding"
        );
    }

    #[test]
    fn test_large_data() {
        let mut rsa = SecureRSA::new();
        rsa.generate_keypair().unwrap();

        let large_data = vec![0u8; 1024 * 1024];
        let encrypted = rsa.encrypt(&large_data).unwrap();
        let decrypted = rsa.decrypt(&encrypted).unwrap();

        assert_eq!(
            large_data, decrypted,
            "Decrypted large data does not match original data"
        );
    }

    #[test]
    fn test_invalid_signature() {
        let mut rsa = SecureRSA::new();
        rsa.generate_keypair().unwrap();

        let data = b"Lorem ipsum dolor sit amet";
        let mut signature = rsa.sign(data).unwrap();

        if let Some(byte) = signature.last_mut() {
            *byte ^= 1;
        }

        assert!(
            !rsa.verify_signature(data, &signature).unwrap(),
            "Modified signature should fail verification"
        );
    }

    #[test]
    fn test_performance() {
        let start = Instant::now();
        let mut rsa = SecureRSA::new();
        rsa.generate_keypair().unwrap();
        let key_generation_duration = start.elapsed();

        let data = b"Lorem ipsum dolor sit amet";
        let iterations = 100;
        let mut total_encryption_time = Duration::new(0, 0);
        let mut total_decryption_time = Duration::new(0, 0);
        let mut total_signing_time = Duration::new(0, 0);
        let mut total_verification_time = Duration::new(0, 0);

        for i in 0..iterations {
            let start = Instant::now();
            let encrypted = rsa.encrypt(data).unwrap();
            total_encryption_time += start.elapsed();

            let start = Instant::now();
            let decrypted = rsa.decrypt(&encrypted).unwrap();
            total_decryption_time += start.elapsed();

            assert_eq!(
                decrypted, data,
                "Decrypted data doesn't match original data at iteration {}",
                i
            );

            let start = Instant::now();
            let signature = rsa.sign(data).unwrap();
            total_signing_time += start.elapsed();

            let start = Instant::now();
            let verified = rsa.verify_signature(data, &signature).unwrap();
            total_verification_time += start.elapsed();

            assert!(verified, "Signature verification failed at iteration {}", i);
        }

        let avg_encryption_time = total_encryption_time / iterations as u32;
        let avg_decryption_time = total_decryption_time / iterations as u32;
        let avg_signing_time = total_signing_time / iterations as u32;
        let avg_verification_time = total_verification_time / iterations as u32;

        println!("Key generation time: {:?}", key_generation_duration);
        println!(
            "Average encryption time over {} iterations: {:?}",
            iterations, avg_encryption_time
        );
        println!(
            "Average decryption time over {} iterations: {:?}",
            iterations, avg_decryption_time
        );
        println!(
            "Average signing time over {} iterations: {:?}",
            iterations, avg_signing_time
        );
        println!(
            "Average verification time over {} iterations: {:?}",
            iterations, avg_verification_time
        );
    }

    #[test]
    fn test_generate_public_key_internal() {
        let mut rsa1 = SecureRSA::new();
        let (private_key, original_public_key) = rsa1.generate_keypair().unwrap();

        let mut rsa2 = SecureRSA::new();
        rsa2.set_private_key(&private_key).unwrap();

        let generated_public_key = rsa2
            .public_key
            .as_ref()
            .unwrap()
            .to_pkcs1_pem(LineEnding::LF)
            .unwrap()
            .as_bytes()
            .to_vec();

        assert_eq!(
            original_public_key, generated_public_key,
            "Internally generated public key does not match original public key"
        );
    }

    #[test]
    fn test_empty_data() {
        let mut rsa = SecureRSA::new();
        rsa.generate_keypair().unwrap();

        let empty_data = b"";
        let encrypted = rsa.encrypt(empty_data).unwrap();
        let decrypted = rsa.decrypt(&encrypted).unwrap();

        assert_eq!(
            empty_data.to_vec(),
            decrypted,
            "Empty data encryption/decryption failed"
        );

        let signature = rsa.sign(empty_data).unwrap();
        assert!(
            rsa.verify_signature(empty_data, &signature).unwrap(),
            "Empty data signature verification failed"
        );
    }

    #[test]
    fn test_invalid_decryption_data() {
        let mut rsa = SecureRSA::new();
        rsa.generate_keypair().unwrap();

        let invalid_data = vec![0u8; 3];
        assert!(
            matches!(rsa.decrypt(&invalid_data), Err(RSAError::InvalidData)),
            "Short invalid data should return InvalidData error"
        );

        let plaintext = b"Lorem ipsum dolor sit amet";
        let mut encrypted = rsa.encrypt(plaintext).unwrap();
        let last_byte = encrypted.last_mut().unwrap();
        *last_byte ^= 0xFF;
        assert!(
            matches!(rsa.decrypt(&encrypted), Err(RSAError::DecryptionError)),
            "Corrupted data should return DecryptionError"
        );
    }

    #[test]
    fn test_key_operations() {
        let mut rsa1 = SecureRSA::new();
        rsa1.generate_keypair().unwrap();

        let mut rsa2 = SecureRSA::new();
        assert!(
            matches!(
                rsa2.set_private_key(b"invalid key"),
                Err(RSAError::InvalidKey)
            ),
            "Setting invalid private key should return InvalidKey error"
        );
        assert!(
            matches!(
                rsa2.set_public_key(b"invalid key"),
                Err(RSAError::InvalidKey)
            ),
            "Setting invalid public key should return InvalidKey error"
        );

        let rsa3 = SecureRSA::new();
        assert!(
            matches!(rsa3.encrypt(b"Lorem"), Err(RSAError::InvalidKey)),
            "Encryption without key should return InvalidKey error"
        );
        assert!(
            matches!(rsa3.decrypt(b"Lorem"), Err(RSAError::InvalidKey)),
            "Decryption without key should return InvalidKey error"
        );
        assert!(
            matches!(rsa3.sign(b"Lorem"), Err(RSAError::InvalidKey)),
            "Signing without key should return InvalidKey error"
        );
        assert!(
            matches!(
                rsa3.verify_signature(b"Lorem", b"sig"),
                Err(RSAError::InvalidKey)
            ),
            "Signature verification without key should return InvalidKey error"
        );
    }

    #[test]
    fn test_cross_instance_operations() {
        let mut rsa1 = SecureRSA::new();
        let (_, public_key) = rsa1.generate_keypair().unwrap();

        let mut rsa2 = SecureRSA::new();
        rsa2.set_public_key(&public_key).unwrap();

        let message = b"Lorem ipsum dolor sit amet";
        let encrypted = rsa2.encrypt(message).unwrap();
        let decrypted = rsa1.decrypt(&encrypted).unwrap();
        assert_eq!(
            message.to_vec(),
            decrypted,
            "Cross-instance encryption/decryption failed to preserve message"
        );

        let signature = rsa1.sign(message).unwrap();
        assert!(
            rsa2.verify_signature(message, &signature).unwrap(),
            "Cross-instance signature verification failed"
        );
    }

    #[test]
    fn test_binary_data() {
        let mut rsa = SecureRSA::new();
        rsa.generate_keypair().unwrap();

        let mut binary_data = Vec::with_capacity(256);
        for i in 0..=255u8 {
            binary_data.push(i);
        }

        let encrypted = rsa.encrypt(&binary_data).unwrap();
        let decrypted = rsa.decrypt(&encrypted).unwrap();

        assert_eq!(
            binary_data, decrypted,
            "Binary data encryption/decryption failed to preserve all byte values"
        );
    }

    #[test]
    fn test_multiple_operations() {
        let mut rsa = SecureRSA::new();
        rsa.generate_keypair().unwrap();

        for i in 0..5 {
            let message = format!("Lorem ipsum dolor sit amet {}", i).into_bytes();
            let encrypted = rsa.encrypt(&message).unwrap();
            let decrypted = rsa.decrypt(&encrypted).unwrap();
            assert_eq!(
                message, decrypted,
                "Multiple encryption/decryption operations failed at iteration {}",
                i
            );
        }

        for i in 0..5 {
            let message = format!("Lorem ipsum dolor sit amet {}", i).into_bytes();
            let signature = rsa.sign(&message).unwrap();
            assert!(
                rsa.verify_signature(&message, &signature).unwrap(),
                "Multiple signature operations failed at iteration {}",
                i
            );
        }
    }

    #[test]
    fn test_key_reuse() {
        let mut rsa1 = SecureRSA::new();
        let (private_key, _) = rsa1.generate_keypair().unwrap();

        for i in 0..3 {
            let mut new_rsa = SecureRSA::new();
            new_rsa.set_private_key(&private_key).unwrap();

            let message = b"Lorem ipsum dolor sit amet";
            let encrypted = new_rsa.encrypt(message).unwrap();
            let decrypted = new_rsa.decrypt(&encrypted).unwrap();
            assert_eq!(
                message.to_vec(),
                decrypted,
                "Key reuse failed in instance {}",
                i
            );
        }
    }

    #[test]
    fn test_memory_protection() {
        let mut rsa = SecureRSA::new();
        let (private_key, _) = rsa.generate_keypair().unwrap();

        assert!(
            rsa.memory_locked,
            "Memory should be locked after key generation"
        );

        drop(rsa);

        let mut rsa2 = SecureRSA::new();
        rsa2.set_private_key(&private_key).unwrap();
        assert!(
            rsa2.memory_locked,
            "Memory should be locked after setting private key"
        );
    }

    #[test]
    fn test_key_size_validation() {
        assert!(
            matches!(
                SecureRSA::validate_key_size(128),
                Err(RSAError::ValidationError)
            ),
            "Should reject key size below minimum (2048 bits)"
        );

        assert!(
            SecureRSA::validate_key_size(256).is_ok(),
            "Should accept key size of 2048 bits"
        );

        assert!(
            SecureRSA::validate_key_size(512).is_ok(),
            "Should accept key size of 4096 bits"
        );
    }

    #[test]
    fn test_secure_buffer_wiping() {
        let mut buffer = vec![0xFFu8; 32];
        SecureRSA::protect_buffer(&mut buffer).unwrap();
        SecureRSA::unprotect_buffer(&mut buffer).unwrap();

        assert!(
            buffer.iter().all(|&b| b == 0),
            "Buffer should be securely wiped to zero after unprotection"
        );
    }

    #[test]
    fn test_constant_time_operations() {
        let mut rsa = SecureRSA::new();
        rsa.generate_keypair().unwrap();
        let data = b"Lorem ipsum dolor sit amet";
        let signature = rsa.sign(data).unwrap();

        for _ in 0..100 {
            let _ = rsa.verify_signature(data, &signature).unwrap();
        }

        let iterations = 1000;
        let mut valid_times = Vec::with_capacity(iterations);
        let mut invalid_times = Vec::with_capacity(iterations);

        for _ in 0..iterations {
            let start = Instant::now();
            let _ = rsa.verify_signature(data, &signature).unwrap();
            valid_times.push(start.elapsed());

            let mut invalid_signature = signature.clone();
            if let Some(byte) = invalid_signature.last_mut() {
                *byte ^= 1;
            }
            let start = Instant::now();
            let _ = rsa.verify_signature(data, &invalid_signature).unwrap();
            invalid_times.push(start.elapsed());
        }

        valid_times.sort();
        invalid_times.sort();
        let trim = iterations / 20;
        let valid_times: Vec<_> = valid_times[trim..iterations - trim].to_vec();
        let invalid_times: Vec<_> = invalid_times[trim..iterations - trim].to_vec();

        let valid_median = valid_times[valid_times.len() / 2];
        let invalid_median = invalid_times[invalid_times.len() / 2];

        let time_diff = if valid_median > invalid_median {
            valid_median.as_nanos() as f64 / invalid_median.as_nanos() as f64
        } else {
            invalid_median.as_nanos() as f64 / valid_median.as_nanos() as f64
        };

        assert!(
            time_diff < 1.2,
            "Timing difference between valid and invalid signatures is too large: {:.2}x. \
            This might indicate a timing side-channel vulnerability",
            time_diff
        );
    }

    #[test]
    fn test_fault_injection_resistance() {
        let mut rsa = SecureRSA::new();
        rsa.generate_keypair().unwrap();

        let data = b"Lorem ipsum dolor sit amet";
        let mut signature = rsa.sign(data).unwrap();

        if let Some(byte) = signature.last_mut() {
            *byte ^= 1;
            assert!(
                !rsa.verify_signature(data, &signature).unwrap(),
                "Modified signature should be rejected"
            );
        }

        let mut modified_data = data.to_vec();
        if let Some(byte) = modified_data.last_mut() {
            *byte ^= 1;
            assert!(
                !rsa.verify_signature(&modified_data, &signature).unwrap(),
                "Signature should be invalid for modified data"
            );
        }
    }

    #[test]
    fn test_memory_cleanup() {
        let mut rsa = SecureRSA::new();
        let (private_key, _) = rsa.generate_keypair().unwrap();

        {
            let mut temp_rsa = SecureRSA::new();
            temp_rsa.set_private_key(&private_key).unwrap();
            assert!(
                temp_rsa.memory_locked,
                "Memory should be locked when private key is set"
            );
        }
    }

    #[test]
    fn test_encryption_padding() {
        let mut rsa = SecureRSA::new();
        rsa.generate_keypair().unwrap();

        let data = b"Lorem ipsum dolor sit amet";

        let encrypted1 = rsa.encrypt(data).unwrap();
        let encrypted2 = rsa.encrypt(data).unwrap();

        assert_ne!(
            encrypted1, encrypted2,
            "Encryption should use random padding - identical ciphertexts detected"
        );

        let decrypted1 = rsa.decrypt(&encrypted1).unwrap();
        let decrypted2 = rsa.decrypt(&encrypted2).unwrap();

        assert_eq!(
            decrypted1, data,
            "First decryption failed to recover original data"
        );
        assert_eq!(
            decrypted2, data,
            "Second decryption failed to recover original data"
        );
    }

    #[test]
    fn test_key_isolation() {
        let mut rsa1 = SecureRSA::new();
        let mut rsa2 = SecureRSA::new();

        rsa1.generate_keypair().unwrap();
        rsa2.generate_keypair().unwrap();

        let data = b"Lorem ipsum dolor sit amet";
        let encrypted = rsa1.encrypt(data).unwrap();

        assert!(
            matches!(rsa2.decrypt(&encrypted), Err(RSAError::DecryptionError)),
            "Decryption with wrong key should fail"
        );
    }

    #[test]
    fn test_error_messages() {
        let rsa = SecureRSA::new();
        let data = b"Lorem ipsum dolor sit amet";

        let err = rsa.encrypt(data).unwrap_err();
        let err_str = format!("{:?}", err);
        assert!(
            !err_str.contains("key"),
            "Error message should not leak sensitive key information"
        );

        let err = rsa.sign(data).unwrap_err();
        let err_str = format!("{:?}", err);
        assert!(
            !err_str.contains("key"),
            "Error message should not leak sensitive key information"
        );
    }

    #[test]
    fn test_protected_operations() {
        let mut rsa = SecureRSA::new();
        rsa.generate_keypair().unwrap();

        let data = b"Lorem ipsum dolor sit amet";

        assert!(
            rsa.memory_locked,
            "Memory should be locked after key generation"
        );

        let encrypted = rsa.encrypt(data).unwrap();
        assert!(
            rsa.memory_locked,
            "Memory should remain locked after encryption"
        );

        let _ = rsa.decrypt(&encrypted).unwrap();
        assert!(
            rsa.memory_locked,
            "Memory should remain locked after decryption"
        );

        let signature = rsa.sign(data).unwrap();
        assert!(
            rsa.memory_locked,
            "Memory should remain locked after signing"
        );

        let _ = rsa.verify_signature(data, &signature).unwrap();
        assert!(
            rsa.memory_locked,
            "Memory should remain locked after signature verification"
        );
    }
}
