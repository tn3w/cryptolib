use libc::{c_void, madvise, mlock, munlock, MADV_DONTDUMP};
use pqcrypto_kyber::kyber1024::{
    decapsulate, encapsulate, keypair, Ciphertext, PublicKey, SecretKey,
};
use pqcrypto_traits::kem::{
    Ciphertext as CiphertextTrait, PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait,
    SharedSecret as SharedSecretTrait,
};
use rand::{rngs::OsRng, RngCore};
use ring::{aead, pbkdf2};
use std::{num::NonZeroU32, ptr, sync::atomic::Ordering};

const NONCE_SIZE: usize = 32;
const SALT_LEN: usize = 32;
const AES_NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const PBKDF2_ITERATIONS: u32 = 100_000;
const MIN_MESSAGE_LEN: usize = 1;
const KYBER1024_CT_LEN: usize = 1568;

#[derive(Debug)]
pub enum KyberError {
    KeyGenerationError,
    EncapsulationError,
    DecapsulationError,
    ValidationError,
    MemoryProtectionError,
    NonceError,
    EncryptionError,
    DecryptionError,
    KeyDerivationError,
}

impl std::fmt::Display for KyberError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyGenerationError => write!(f, "Key generation failed"),
            Self::EncapsulationError => write!(f, "Encapsulation failed"),
            Self::DecapsulationError => write!(f, "Decapsulation failed"),
            Self::ValidationError => write!(f, "Input validation failed"),
            Self::MemoryProtectionError => write!(f, "Memory protection failed"),
            Self::NonceError => write!(f, "Nonce generation failed"),
            Self::EncryptionError => write!(f, "Encryption failed"),
            Self::DecryptionError => write!(f, "Decryption failed"),
            Self::KeyDerivationError => write!(f, "Key derivation failed"),
        }
    }
}

/// A secure Kyber post-quantum key encapsulation implementation with memory protection.
pub struct SecureKyber {
    public_key: Option<PublicKey>,
    secret_key: Option<Vec<u8>>,
    memory_locked: bool,
}

impl SecureKyber {
    /// Creates a new Kyber key encapsulation instance.
    pub fn new() -> Self {
        Self {
            public_key: None,
            secret_key: None,
            memory_locked: false,
        }
    }

    fn secure_zero(buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            unsafe { ptr::write_volatile(byte, 0) };
        }
        std::sync::atomic::fence(Ordering::SeqCst);
    }

    fn protect_buffer(buf: &mut [u8]) -> Result<(), KyberError> {
        let ptr = buf.as_ptr() as *const c_void;
        let size = buf.len();

        unsafe {
            mlock(ptr, size);
            madvise(ptr as *mut c_void, size, MADV_DONTDUMP);
        }
        Ok(())
    }

    fn unprotect_buffer(buf: &mut [u8]) -> Result<(), KyberError> {
        let ptr = buf.as_ptr() as *const c_void;
        let size = buf.len();
        unsafe { munlock(ptr, size) };
        Self::secure_zero(buf);
        Ok(())
    }

    fn lock_memory(&mut self) -> Result<(), KyberError> {
        if self.memory_locked {
            return Ok(());
        }

        if let Some(ref secret_key) = self.secret_key {
            let ptr = secret_key.as_ptr() as *const c_void;
            let size = secret_key.len();

            unsafe {
                mlock(ptr, size);
                madvise(ptr as *mut c_void, size, MADV_DONTDUMP);
            }
            self.memory_locked = true;
        }
        Ok(())
    }

    fn unlock_memory(&mut self) -> Result<(), KyberError> {
        if !self.memory_locked {
            return Ok(());
        }

        if let Some(ref secret_key) = self.secret_key {
            let ptr = secret_key.as_ptr() as *const c_void;
            let size = secret_key.len();
            unsafe { munlock(ptr, size) };
        }
        self.memory_locked = false;
        Ok(())
    }

    fn generate_nonce() -> Result<Vec<u8>, KyberError> {
        let mut nonce = vec![0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);
        Ok(nonce)
    }

    /// Generates a new Kyber key pair (NIST Level 5 security).
    ///
    /// # Returns
    /// * `Result<(Vec<u8>, Vec<u8>), KyberError>` - (private_key, public_key) or an error
    pub fn generate_keypair(&mut self) -> Result<(Vec<u8>, Vec<u8>), KyberError> {
        self.unlock_memory().ok();

        let (pk, sk) = keypair();

        let mut private_key = sk.as_bytes().to_vec();
        Self::protect_buffer(&mut private_key)?;

        let public_key = pk.as_bytes().to_vec();

        self.public_key = Some(pk);
        self.secret_key = Some(private_key.clone());

        self.lock_memory()?;

        let result = (private_key.clone(), public_key);
        Self::unprotect_buffer(&mut private_key)?;

        Ok(result)
    }

    /// Creates a Kyber instance from an existing public key.
    ///
    /// # Arguments
    /// * `public_key` - The public key bytes
    ///
    /// # Returns
    /// * `Result<Self, KyberError>` - A new instance for encryption only
    pub fn from_public_key(public_key: &[u8]) -> Result<Self, KyberError> {
        let pk = PublicKey::from_bytes(public_key).map_err(|_| KyberError::ValidationError)?;

        Ok(Self {
            public_key: Some(pk),
            secret_key: None,
            memory_locked: false,
        })
    }

    /// Performs key encapsulation to generate a shared secret.
    ///
    /// # Returns
    /// * `Result<(Vec<u8>, Vec<u8>), KyberError>` - (ciphertext, shared_secret) or an error
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), KyberError> {
        let public_key = self
            .public_key
            .as_ref()
            .ok_or(KyberError::ValidationError)?;

        let nonce = Self::generate_nonce()?;
        let mut protected_nonce = nonce.clone();
        Self::protect_buffer(&mut protected_nonce)?;

        let (ss, ct) = encapsulate(public_key);
        let mut ss_bytes = ss.as_bytes().to_vec();
        Self::protect_buffer(&mut ss_bytes)?;

        let mut combined = Vec::with_capacity(NONCE_SIZE + ct.as_bytes().len());
        combined.extend_from_slice(&nonce);
        combined.extend_from_slice(ct.as_bytes());

        let result = (combined, ss_bytes.clone());

        Self::unprotect_buffer(&mut protected_nonce)?;
        Self::unprotect_buffer(&mut ss_bytes)?;

        Ok(result)
    }

    /// Decapsulates a ciphertext to recover the shared secret.
    ///
    /// # Arguments
    /// * `ciphertext` - The encapsulated key material
    ///
    /// # Returns
    /// * `Result<Vec<u8>, KyberError>` - The shared secret or an error
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, KyberError> {
        if ciphertext.len() <= NONCE_SIZE {
            return Err(KyberError::ValidationError);
        }

        let secret_key = self
            .secret_key
            .as_ref()
            .ok_or(KyberError::ValidationError)?;

        let (nonce, ct_bytes) = ciphertext.split_at(NONCE_SIZE);
        let mut protected_nonce = nonce.to_vec();
        Self::protect_buffer(&mut protected_nonce)?;

        let sk = SecretKey::from_bytes(secret_key).map_err(|_| KyberError::ValidationError)?;

        let ct = Ciphertext::from_bytes(ct_bytes).map_err(|_| KyberError::ValidationError)?;

        let ss = decapsulate(&ct, &sk);
        let mut ss_bytes = ss.as_bytes().to_vec();
        Self::protect_buffer(&mut ss_bytes)?;

        let result = ss_bytes.clone();

        Self::unprotect_buffer(&mut protected_nonce)?;
        Self::unprotect_buffer(&mut ss_bytes)?;

        Ok(result)
    }

    /// Clears all sensitive data from memory.
    pub fn clear_sensitive_data(&mut self) {
        self.unlock_memory().ok();

        if let Some(ref mut secret_key) = self.secret_key {
            let ptr = secret_key.as_ptr() as *mut u8;
            let size = secret_key.len();
            unsafe {
                for i in 0..size {
                    ptr::write_volatile(ptr.add(i) as *mut u8, 0);
                }
            }
        }

        self.secret_key = None;
        self.public_key = None;
        self.memory_locked = false;

        std::sync::atomic::fence(Ordering::SeqCst);
    }

    fn derive_key(shared_secret: &[u8], salt: &[u8]) -> Result<aead::LessSafeKey, KyberError> {
        let mut key_bytes = [0u8; KEY_LEN];
        Self::protect_buffer(&mut key_bytes)?;

        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
            salt,
            shared_secret,
            &mut key_bytes,
        );

        let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes)
            .map_err(|_| KyberError::KeyDerivationError)?;

        Self::unprotect_buffer(&mut key_bytes)?;

        Ok(aead::LessSafeKey::new(unbound_key))
    }

    fn validate_message(message: &[u8]) -> Result<(), KyberError> {
        if message.len() < MIN_MESSAGE_LEN {
            return Err(KyberError::ValidationError);
        }
        Ok(())
    }

    /// Encrypts data using Kyber KEM with AES-256-GCM.
    ///
    /// # Arguments
    /// * `plaintext` - The data to encrypt
    ///
    /// # Returns
    /// * `Result<Vec<u8>, KyberError>` - The encrypted data or an error
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, KyberError> {
        Self::validate_message(plaintext)?;

        let public_key = self
            .public_key
            .as_ref()
            .ok_or(KyberError::ValidationError)?;

        let mut salt = [0u8; SALT_LEN];
        let mut aes_nonce = [0u8; AES_NONCE_LEN];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut aes_nonce);

        let mut protected_salt = salt.to_vec();
        let mut protected_nonce = aes_nonce.to_vec();
        Self::protect_buffer(&mut protected_salt)?;
        Self::protect_buffer(&mut protected_nonce)?;

        let (ss, ct) = encapsulate(public_key);
        let mut ss_bytes = ss.as_bytes().to_vec();
        Self::protect_buffer(&mut ss_bytes)?;

        let key = Self::derive_key(&ss_bytes, &salt)?;

        let mut in_out = plaintext.to_vec();
        Self::protect_buffer(&mut in_out)?;

        let aead_nonce = aead::Nonce::assume_unique_for_key(aes_nonce);
        key.seal_in_place_append_tag(aead_nonce, aead::Aad::empty(), &mut in_out)
            .map_err(|_| KyberError::EncryptionError)?;

        let mut result =
            Vec::with_capacity(SALT_LEN + AES_NONCE_LEN + ct.as_bytes().len() + in_out.len());
        result.extend_from_slice(&salt);
        result.extend_from_slice(&aes_nonce);
        result.extend_from_slice(ct.as_bytes());
        result.extend_from_slice(&in_out);

        Self::unprotect_buffer(&mut protected_salt)?;
        Self::unprotect_buffer(&mut protected_nonce)?;
        Self::unprotect_buffer(&mut ss_bytes)?;
        Self::unprotect_buffer(&mut in_out)?;

        Ok(result)
    }

    /// Decrypts data using Kyber KEM with AES-256-GCM.
    ///
    /// # Arguments
    /// * `ciphertext` - The encrypted data
    ///
    /// # Returns
    /// * `Result<Vec<u8>, KyberError>` - The decrypted data or an error
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, KyberError> {
        let secret_key = self
            .secret_key
            .as_ref()
            .ok_or(KyberError::ValidationError)?;

        if ciphertext.len() <= SALT_LEN + AES_NONCE_LEN + KYBER1024_CT_LEN {
            return Err(KyberError::ValidationError);
        }

        let (salt, rest) = ciphertext.split_at(SALT_LEN);
        let (aes_nonce, rest) = rest.split_at(AES_NONCE_LEN);
        let (kyber_ct, encrypted_data) = rest.split_at(KYBER1024_CT_LEN);

        let mut protected_salt = salt.to_vec();
        let mut protected_nonce = aes_nonce.to_vec();
        Self::protect_buffer(&mut protected_salt)?;
        Self::protect_buffer(&mut protected_nonce)?;

        let sk = SecretKey::from_bytes(secret_key).map_err(|_| KyberError::ValidationError)?;
        let ct = Ciphertext::from_bytes(kyber_ct).map_err(|_| KyberError::ValidationError)?;
        let ss = decapsulate(&ct, &sk);
        let mut ss_bytes = ss.as_bytes().to_vec();
        Self::protect_buffer(&mut ss_bytes)?;

        let key = Self::derive_key(&ss_bytes, salt)?;

        let mut decrypted_data = encrypted_data.to_vec();
        Self::protect_buffer(&mut decrypted_data)?;

        let aead_nonce = aead::Nonce::assume_unique_for_key(
            aes_nonce
                .try_into()
                .map_err(|_| KyberError::DecryptionError)?,
        );

        let decrypted_len = key
            .open_in_place(aead_nonce, aead::Aad::empty(), &mut decrypted_data)
            .map_err(|_| KyberError::DecryptionError)?
            .len();

        decrypted_data.truncate(decrypted_len);

        Self::unprotect_buffer(&mut protected_salt)?;
        Self::unprotect_buffer(&mut protected_nonce)?;
        Self::unprotect_buffer(&mut ss_bytes)?;

        let result = decrypted_data.clone();
        Self::unprotect_buffer(&mut decrypted_data)?;

        Ok(result)
    }

    /// Sets the private key for decryption operations.
    ///
    /// # Arguments
    /// * `private_key` - The private key bytes
    ///
    /// # Returns
    /// * `Result<(), KyberError>` - Success or an error
    pub fn set_private_key(&mut self, private_key: &[u8]) -> Result<(), KyberError> {
        self.unlock_memory().ok();

        SecretKey::from_bytes(private_key).map_err(|_| KyberError::ValidationError)?;

        let mut protected_secret = private_key.to_vec();
        Self::protect_buffer(&mut protected_secret)?;

        self.secret_key = Some(protected_secret);
        self.lock_memory()?;

        Ok(())
    }
}

impl Drop for SecureKyber {
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
        let mut kyber = SecureKyber::new();
        let (private_key, public_key) = kyber
            .generate_keypair()
            .expect("Failed to generate keypair");
        assert!(!private_key.is_empty(), "Private key should not be empty");
        assert!(!public_key.is_empty(), "Public key should not be empty");
        assert!(
            kyber.memory_locked,
            "Memory should be locked after key generation"
        );
    }

    #[test]
    fn test_encapsulation_decapsulation() {
        let mut kyber = SecureKyber::new();
        kyber
            .generate_keypair()
            .expect("Failed to generate keypair");
        let (ciphertext, shared_secret1) = kyber.encapsulate().expect("Failed to encapsulate");
        let shared_secret2 = kyber
            .decapsulate(&ciphertext)
            .expect("Failed to decapsulate");
        assert_eq!(
            shared_secret1, shared_secret2,
            "Shared secrets don't match after encapsulation/decapsulation"
        );
    }

    #[test]
    fn test_memory_protection() {
        let mut data = vec![0u8; 32];
        SecureKyber::protect_buffer(&mut data).expect("Failed to protect buffer");
        SecureKyber::unprotect_buffer(&mut data).expect("Failed to unprotect buffer");
        assert!(
            data.iter().all(|&x| x == 0),
            "Buffer should be zeroed after unprotection"
        );
    }

    #[test]
    fn test_public_key_only() {
        let mut kyber = SecureKyber::new();
        let (_, public_key) = kyber
            .generate_keypair()
            .expect("Failed to generate keypair");

        let public_only = SecureKyber::from_public_key(&public_key)
            .expect("Failed to create instance from public key");
        assert!(
            public_only.public_key.is_some(),
            "Public key should be present"
        );
        assert!(
            public_only.secret_key.is_none(),
            "Secret key should not be present in public-key-only instance"
        );

        let (ct, ss1) = kyber.encapsulate().expect("Failed to encapsulate");
        let ss2 = kyber.decapsulate(&ct).expect("Failed to decapsulate");
        assert_eq!(ss1, ss2, "Shared secrets don't match in original instance");

        assert!(
            public_only.decapsulate(&ct).is_err(),
            "Decapsulation should fail with public key only"
        );
    }

    #[test]
    fn test_different_ciphertexts() {
        let mut kyber = SecureKyber::new();
        let (_, _) = kyber
            .generate_keypair()
            .expect("Failed to generate keypair");
        let (ct1, ss1) = kyber.encapsulate().expect("First encapsulation failed");
        let (ct2, ss2) = kyber.encapsulate().expect("Second encapsulation failed");

        assert_ne!(
            ct1, ct2,
            "Ciphertexts should be different for different encapsulations"
        );
        assert_ne!(
            ss1, ss2,
            "Shared secrets should be different for different encapsulations"
        );
    }

    #[test]
    fn test_memory_cleanup() {
        let mut kyber = SecureKyber::new();
        let (_, _) = kyber
            .generate_keypair()
            .expect("Failed to generate keypair");
        assert!(
            kyber.memory_locked,
            "Memory should be locked after key generation"
        );

        kyber.clear_sensitive_data();
        assert!(
            !kyber.memory_locked,
            "Memory should be unlocked after clearing sensitive data"
        );
        assert!(
            kyber.secret_key.is_none(),
            "Secret key should be cleared after clearing sensitive data"
        );
        assert!(
            kyber.public_key.is_none(),
            "Public key should be cleared after clearing sensitive data"
        );
    }

    #[test]
    fn test_cross_instance_operations() {
        let mut kyber1 = SecureKyber::new();
        let (_, public_key) = kyber1
            .generate_keypair()
            .expect("Failed to generate first keypair");

        let kyber2 = SecureKyber::from_public_key(&public_key)
            .expect("Failed to create second instance from public key");
        let (ct, ss1) = kyber2
            .encapsulate()
            .expect("Failed to encapsulate in second instance");
        let ss2 = kyber1
            .decapsulate(&ct)
            .expect("Failed to decapsulate in first instance");

        assert_eq!(ss1, ss2, "Cross-instance shared secrets don't match");
    }

    #[test]
    fn test_invalid_data() {
        let mut kyber = SecureKyber::new();
        let (_, _) = kyber
            .generate_keypair()
            .expect("Failed to generate keypair");

        let invalid_ct = vec![0u8; 32];
        assert!(
            kyber.decapsulate(&invalid_ct).is_err(),
            "Should reject invalid ciphertext"
        );

        let invalid_pk = vec![0u8; 32];
        assert!(
            SecureKyber::from_public_key(&invalid_pk).is_err(),
            "Should reject invalid public key"
        );
    }

    #[test]
    fn test_protected_operations() {
        let mut kyber = SecureKyber::new();
        let (_, _) = kyber
            .generate_keypair()
            .expect("Failed to generate keypair");
        assert!(
            kyber.memory_locked,
            "Memory should be locked after key generation"
        );

        let (ct, _) = kyber.encapsulate().expect("Failed to encapsulate");
        assert!(
            kyber.memory_locked,
            "Memory should remain locked after encapsulation"
        );

        let _ = kyber.decapsulate(&ct).expect("Failed to decapsulate");
        assert!(
            kyber.memory_locked,
            "Memory should remain locked after decapsulation"
        );

        kyber.clear_sensitive_data();
        assert!(
            !kyber.memory_locked,
            "Memory should be unlocked after clearing sensitive data"
        );
    }

    #[test]
    fn test_encryption_decryption() {
        let mut kyber = SecureKyber::new();
        let (_, _) = kyber
            .generate_keypair()
            .expect("Failed to generate keypair");
        let plaintext = b"Hello, secure world!";
        let encrypted = kyber.encrypt(plaintext).expect("Failed to encrypt message");
        let decrypted = kyber
            .decrypt(&encrypted)
            .expect("Failed to decrypt message");
        assert_eq!(
            plaintext.to_vec(),
            decrypted,
            "Decrypted message doesn't match original plaintext"
        );
    }

    #[test]
    fn test_different_encryptions() {
        let mut kyber = SecureKyber::new();
        let (_, _) = kyber
            .generate_keypair()
            .expect("Failed to generate keypair");
        let plaintext = b"Hello, secure world!";
        let encrypted1 = kyber.encrypt(plaintext).expect("First encryption failed");
        let encrypted2 = kyber.encrypt(plaintext).expect("Second encryption failed");
        assert_ne!(
            encrypted1, encrypted2,
            "Different encryptions of the same message should produce different ciphertexts"
        );

        let decrypted1 = kyber.decrypt(&encrypted1).expect("First decryption failed");
        let decrypted2 = kyber
            .decrypt(&encrypted2)
            .expect("Second decryption failed");
        assert_eq!(
            decrypted1, decrypted2,
            "Decrypted texts from different encryptions should match"
        );
        assert_eq!(
            plaintext.to_vec(),
            decrypted1,
            "Decrypted text should match original plaintext"
        );
    }

    #[test]
    fn test_large_data_encryption() {
        let mut kyber = SecureKyber::new();
        let (_, _) = kyber
            .generate_keypair()
            .expect("Failed to generate keypair");
        let large_data = vec![0u8; 1024 * 1024];
        let encrypted = kyber
            .encrypt(&large_data)
            .expect("Failed to encrypt large data");
        let decrypted = kyber
            .decrypt(&encrypted)
            .expect("Failed to decrypt large data");
        assert_eq!(
            large_data, decrypted,
            "Decrypted large data doesn't match original"
        );
    }

    #[test]
    fn test_invalid_encryption_data() {
        let mut kyber = SecureKyber::new();
        let (_, _) = kyber
            .generate_keypair()
            .expect("Failed to generate keypair");

        assert!(kyber.encrypt(&[]).is_err(), "Should reject empty data");

        let invalid_data = vec![0u8; SALT_LEN + AES_NONCE_LEN - 1];
        assert!(
            kyber.decrypt(&invalid_data).is_err(),
            "Should reject ciphertext smaller than minimum required size"
        );
    }

    #[test]
    fn test_cross_instance_encryption() {
        let mut kyber1 = SecureKyber::new();
        let (_, public_key) = kyber1
            .generate_keypair()
            .expect("Failed to generate first keypair");

        let kyber2 = SecureKyber::from_public_key(&public_key)
            .expect("Failed to create second instance from public key");
        let plaintext = b"Hello, secure world!";
        let encrypted = kyber2
            .encrypt(plaintext)
            .expect("Failed to encrypt in second instance");
        let decrypted = kyber1
            .decrypt(&encrypted)
            .expect("Failed to decrypt in first instance");

        assert_eq!(
            plaintext.to_vec(),
            decrypted,
            "Cross-instance encryption/decryption failed to preserve message"
        );
    }

    #[test]
    fn test_performance() {
        let start = Instant::now();
        let mut kyber = SecureKyber::new();
        let (_, _) = kyber
            .generate_keypair()
            .expect("Failed to generate keypair");
        let key_generation_duration = start.elapsed();

        let data = b"Lorem ipsum dolor sit amet";
        let iterations = 100;
        let mut total_encryption_time = Duration::new(0, 0);
        let mut total_decryption_time = Duration::new(0, 0);

        for i in 0..iterations {
            let start = Instant::now();
            let encrypted = kyber
                .encrypt(data)
                .expect(&format!("Failed to encrypt at iteration {}", i));
            total_encryption_time += start.elapsed();

            let start = Instant::now();
            let decrypted = kyber
                .decrypt(&encrypted)
                .expect(&format!("Failed to decrypt at iteration {}", i));
            total_decryption_time += start.elapsed();

            assert_eq!(decrypted, data, "Data mismatch at iteration {}", i);
        }

        let avg_encryption_time = total_encryption_time / iterations as u32;
        let avg_decryption_time = total_decryption_time / iterations as u32;

        println!("Key generation time: {:?}", key_generation_duration);
        println!(
            "Average encryption time over {} iterations: {:?}",
            iterations, avg_encryption_time
        );
        println!(
            "Average decryption time over {} iterations: {:?}",
            iterations, avg_decryption_time
        );

        kyber.clear_sensitive_data();
        assert!(
            !kyber.memory_locked,
            "Memory should be unlocked after performance test"
        );
    }
}
