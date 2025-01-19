use arrayref::array_ref;
use libc::{c_void, madvise, mlock, munlock, MADV_DONTDUMP};
use rand::{rngs::OsRng, Rng};
use ring::{aead, pbkdf2};
use std::{num::NonZeroU32, ptr, sync::atomic::Ordering};

// OWASP recommended parameters
// https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#algorithms
const SALT_LEN: usize = 32; // 256 bits
const NONCE_LEN: usize = 12; // 96 bits
const KEY_LEN: usize = 32; // 256 bits
const TAG_LEN: usize = 16; // 128 bits
const PBKDF2_ITERATIONS: u32 = 100_000;
const MIN_SECRET_LEN: usize = 16;
const MAX_SECRET_LEN: usize = 1024;

#[derive(Debug)]
pub enum AESError {
    KeyDerivationError,
    AESError,
    DecryptionError,
    InvalidData,
    ValidationError,
    MemoryProtectionError,
}

impl std::fmt::Display for AESError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyDerivationError => write!(f, "Key derivation failed"),
            Self::AESError => write!(f, "Encryption failed"),
            Self::DecryptionError => write!(f, "Decryption failed"),
            Self::InvalidData => write!(f, "Invalid data provided"),
            Self::ValidationError => write!(f, "Input validation failed"),
            Self::MemoryProtectionError => write!(f, "Memory protection failed"),
        }
    }
}

/// A secure AES-256-GCM implementation with memory protection.
pub struct SecureAES {
    secret: Vec<u8>,
}

impl SecureAES {
    /// Creates a new AES-256-GCM encryption instance with the provided secret key.
    ///
    /// # Arguments
    /// * `secret` - The secret key (16-1024 bytes) used for encryption/decryption
    ///
    /// # Returns
    /// * `Result<SecureAES, AESError>` - A new SecureAES instance or an error
    pub fn new(secret: &[u8]) -> Result<Self, AESError> {
        Self::validate_secret(secret)?;
        let mut protected_secret = secret.to_vec();
        Self::protect_buffer(&mut protected_secret)?;
        Ok(Self {
            secret: protected_secret,
        })
    }

    fn secure_zero(buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            unsafe { ptr::write_volatile(byte, 0) };
        }
        std::sync::atomic::fence(Ordering::SeqCst);
    }

    fn protect_buffer(buf: &mut [u8]) -> Result<(), AESError> {
        let ptr = buf.as_ptr() as *const c_void;
        let size = buf.len();

        unsafe {
            let _ = mlock(ptr, size);
            let _ = madvise(ptr as *mut c_void, size, MADV_DONTDUMP);
        }
        Ok(())
    }

    fn unprotect_buffer(buf: &mut [u8]) -> Result<(), AESError> {
        let ptr = buf.as_ptr() as *const c_void;
        let size = buf.len();
        unsafe {
            let _ = munlock(ptr, size);
        }
        Self::secure_zero(buf);
        Ok(())
    }

    fn validate_secret(secret: &[u8]) -> Result<(), AESError> {
        if secret.len() < MIN_SECRET_LEN || secret.len() > MAX_SECRET_LEN {
            return Err(AESError::ValidationError);
        }
        Ok(())
    }

    fn derive_key(secret: &[u8], salt: &[u8]) -> Result<aead::LessSafeKey, AESError> {
        let mut key_bytes = [0u8; KEY_LEN];

        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
            salt,
            secret,
            &mut key_bytes,
        );

        let mut protected_key = key_bytes;
        Self::protect_buffer(&mut protected_key)?;

        let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &protected_key)
            .map_err(|_| AESError::KeyDerivationError)?;

        Self::unprotect_buffer(&mut protected_key)?;

        Ok(aead::LessSafeKey::new(unbound_key))
    }

    /// Encrypts data using AES-256-GCM with a unique salt and nonce.
    ///
    /// # Arguments
    /// * `plaintext` - The data to encrypt
    ///
    /// # Returns
    /// * `Result<Vec<u8>, AESError>` - Encrypted data (salt + nonce + ciphertext + tag) or an error
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, AESError> {
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill(&mut salt);

        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill(&mut nonce_bytes);

        let mut protected_salt = salt.to_vec();
        Self::protect_buffer(&mut protected_salt)?;

        let key = Self::derive_key(&self.secret, &protected_salt)?;

        let mut in_out = plaintext.to_vec();
        Self::protect_buffer(&mut in_out)?;

        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
        key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
            .map_err(|_| AESError::AESError)?;

        let mut result = Vec::with_capacity(SALT_LEN + NONCE_LEN + in_out.len());
        result.extend_from_slice(&protected_salt);
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&in_out);

        Self::unprotect_buffer(&mut protected_salt)?;
        Self::unprotect_buffer(&mut in_out)?;

        Ok(result)
    }

    /// Decrypts AES-256-GCM encrypted data with authentication.
    ///
    /// # Arguments
    /// * `encrypted_data` - The encrypted data (salt + nonce + ciphertext + tag)
    ///
    /// # Returns
    /// * `Result<Vec<u8>, AESError>` - Decrypted data or an error if authentication fails
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, AESError> {
        if encrypted_data.len() < SALT_LEN + NONCE_LEN + TAG_LEN {
            return Err(AESError::InvalidData);
        }

        let salt = array_ref!(encrypted_data, 0, SALT_LEN);
        let mut protected_salt = salt.to_vec();
        Self::protect_buffer(&mut protected_salt)?;

        let key = Self::derive_key(&self.secret, &protected_salt)?;

        let nonce_bytes = array_ref!(encrypted_data, SALT_LEN, NONCE_LEN);
        let ciphertext = &encrypted_data[SALT_LEN + NONCE_LEN..];

        let nonce = aead::Nonce::assume_unique_for_key(*nonce_bytes);
        let mut decrypted = ciphertext.to_vec();
        Self::protect_buffer(&mut decrypted)?;

        key.open_in_place(nonce, aead::Aad::empty(), &mut decrypted)
            .map_err(|_| AESError::DecryptionError)?;

        decrypted.truncate(decrypted.len() - TAG_LEN);
        Self::unprotect_buffer(&mut protected_salt)?;

        Ok(decrypted)
    }
}

impl Drop for SecureAES {
    fn drop(&mut self) {
        Self::unprotect_buffer(&mut self.secret).ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn test_encrypt_decrypt_valid_data() {
        let secret = b"my_secure_secret_key";
        let plaintext = b"Hello, secure world!";

        let encryptor = SecureAES::new(secret).unwrap();
        let encrypted = encryptor.encrypt(plaintext).unwrap();
        let decrypted = encryptor.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_different_ciphertexts() {
        let secret = b"my_secure_secret_key";
        let plaintext = b"Same plaintext";

        let encryptor = SecureAES::new(secret).unwrap();
        let encrypted1 = encryptor.encrypt(plaintext).unwrap();
        let encrypted2 = encryptor.encrypt(plaintext).unwrap();

        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn test_wrong_key() {
        let secret1 = b"first_secret_key_123";
        let secret2 = b"different_secret_123";
        let plaintext = b"Secret message";

        let encryptor1 = SecureAES::new(secret1).unwrap();
        let encryptor2 = SecureAES::new(secret2).unwrap();
        let encrypted = encryptor1.encrypt(plaintext).unwrap();

        assert!(encryptor2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_tampered_data() {
        let secret = b"my_secure_secret_key";
        let plaintext = b"Secret message";

        let encryptor = SecureAES::new(secret).unwrap();
        let mut encrypted = encryptor.encrypt(plaintext).unwrap();

        if let Some(byte) = encrypted.last_mut() {
            *byte ^= 1;
        }

        assert!(encryptor.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let secret = b"my_secure_secret_key";
        let plaintext = b"";

        let encryptor = SecureAES::new(secret).unwrap();
        let encrypted = encryptor.encrypt(plaintext).unwrap();
        let decrypted = encryptor.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_large_plaintext() {
        let secret = b"my_secure_secret_key";
        let plaintext = vec![0u8; 1024 * 1024];

        let encryptor = SecureAES::new(secret).unwrap();
        let encrypted = encryptor.encrypt(&plaintext).unwrap();
        let decrypted = encryptor.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_memory_protection() {
        let mut buffer = vec![0xFFu8; 32];
        SecureAES::protect_buffer(&mut buffer).unwrap();
        SecureAES::unprotect_buffer(&mut buffer).unwrap();

        assert!(
            buffer.iter().all(|&b| b == 0),
            "Buffer should be securely wiped after unprotection"
        );
    }

    #[test]
    fn test_input_validation() {
        let short_secret = b"short";
        assert!(matches!(
            SecureAES::new(short_secret),
            Err(AESError::ValidationError)
        ));

        let long_secret = vec![b'a'; MAX_SECRET_LEN + 1];
        assert!(matches!(
            SecureAES::new(&long_secret),
            Err(AESError::ValidationError)
        ));
    }

    #[test]
    fn test_constant_time_decryption() {
        let secret = b"lorem_ipsum_dolor_sit_amet";
        let plaintext = b"Lorem ipsum dolor sit amet";
        let encryptor = SecureAES::new(secret).unwrap();
        let valid_encrypted = encryptor.encrypt(plaintext).unwrap();
        let invalid_encrypted = vec![0u8; valid_encrypted.len()];

        let iterations = 100;
        let mut valid_times = Vec::with_capacity(iterations);
        let mut invalid_times = Vec::with_capacity(iterations);

        for _ in 0..10 {
            let _ = encryptor.decrypt(&valid_encrypted);
            let _ = encryptor.decrypt(&invalid_encrypted);
        }

        for _ in 0..iterations {
            let start = Instant::now();
            let _ = encryptor.decrypt(&valid_encrypted);
            valid_times.push(start.elapsed());

            let start = Instant::now();
            let _ = encryptor.decrypt(&invalid_encrypted);
            invalid_times.push(start.elapsed());
        }

        valid_times.sort();
        invalid_times.sort();

        let trim = iterations / 20;
        let valid_times = &valid_times[trim..iterations - trim];
        let invalid_times = &invalid_times[trim..iterations - trim];

        let valid_median = valid_times[valid_times.len() / 2];
        let invalid_median = invalid_times[invalid_times.len() / 2];

        let time_diff = if valid_median > invalid_median {
            valid_median.as_nanos() as f64 / invalid_median.as_nanos() as f64
        } else {
            invalid_median.as_nanos() as f64 / valid_median.as_nanos() as f64
        };

        assert!(
            time_diff < 1.5,
            "Timing difference between valid and invalid decryption is too large: {:.2}x",
            time_diff
        );
    }

    #[test]
    fn test_performance() {
        let secret = b"lorem_ipsum_dolor_sit_amet";
        let data = b"Lorem ipsum dolor sit amet";

        let start = Instant::now();
        let encryptor = SecureAES::new(secret).unwrap();
        let setup_time = start.elapsed();

        let iterations = 100;
        let mut total_encryption_time = Duration::new(0, 0);
        let mut total_decryption_time = Duration::new(0, 0);

        for i in 0..iterations {
            let start = Instant::now();
            let encrypted = encryptor.encrypt(data).unwrap();
            total_encryption_time += start.elapsed();

            let start = Instant::now();
            let decrypted = encryptor.decrypt(&encrypted).unwrap();
            total_decryption_time += start.elapsed();

            assert_eq!(
                decrypted, data,
                "Decrypted data doesn't match original data at iteration {}",
                i
            );
        }

        let avg_encryption_time = total_encryption_time / iterations as u32;
        let avg_decryption_time = total_decryption_time / iterations as u32;

        println!("Setup time: {:?}", setup_time);
        println!(
            "Average encryption time over {} iterations: {:?}",
            iterations, avg_encryption_time
        );
        println!(
            "Average decryption time over {} iterations: {:?}",
            iterations, avg_decryption_time
        );
    }
}
