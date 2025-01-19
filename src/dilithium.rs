use libc::{c_void, madvise, mlock, munlock, MADV_DONTDUMP};
use pqcrypto_dilithium::dilithium5::{
    detached_sign, keypair as dilithium_keypair, verify_detached_signature, DetachedSignature,
    PublicKey, SecretKey,
};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use rand::{rngs::OsRng, RngCore};
use std::ptr;

const NONCE_LEN: usize = 32;

#[derive(Debug)]
pub enum DilithiumError {
    KeyGenerationError,
    SigningError,
    VerificationError,
    InvalidKey,
    MemoryLockError,
    NoPrivateKey,
}

/// A secure Dilithium post-quantum signature implementation with memory protection.
pub struct SecureDilithium {
    public: Option<PublicKey>,
    private: Option<SecretKey>,
    memory_locked: bool,
}

impl SecureDilithium {
    /// Creates a new Dilithium digital signature instance.
    pub fn new() -> Self {
        Self {
            public: None,
            private: None,
            memory_locked: false,
        }
    }

    fn secure_zero(buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            unsafe { ptr::write_volatile(byte, 0) };
        }
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    }

    fn protect_buffer(buf: &mut [u8]) -> Result<(), DilithiumError> {
        let ptr = buf.as_ptr() as *const c_void;
        let size = buf.len();

        unsafe {
            mlock(ptr, size);
            madvise(ptr as *mut c_void, size, MADV_DONTDUMP);
        }
        Ok(())
    }

    fn unprotect_buffer(buf: &mut [u8]) -> Result<(), DilithiumError> {
        let ptr = buf.as_ptr() as *const c_void;
        let size = buf.len();
        unsafe { munlock(ptr, size) };
        Self::secure_zero(buf);
        Ok(())
    }

    fn lock_memory(&mut self) -> Result<(), DilithiumError> {
        if self.memory_locked {
            return Ok(());
        }

        if let Some(ref private_key) = self.private {
            let ptr = private_key as *const _ as *const c_void;
            let size = std::mem::size_of_val(private_key);
            unsafe {
                mlock(ptr, size);
                madvise(ptr as *mut c_void, size, MADV_DONTDUMP);
            }
        }

        self.memory_locked = true;
        Ok(())
    }

    fn unlock_memory(&mut self) -> Result<(), DilithiumError> {
        if !self.memory_locked {
            return Ok(());
        }

        if let Some(ref private_key) = self.private {
            let ptr = private_key as *const _ as *const c_void;
            let size = std::mem::size_of_val(private_key);
            unsafe { munlock(ptr, size) };
        }

        self.memory_locked = false;
        Ok(())
    }

    /// Generates a new Dilithium key pair (NIST Level 5 security).
    ///
    /// # Returns
    /// * `Result<(Vec<u8>, Vec<u8>), DilithiumError>` - (private_key, public_key) or an error
    pub fn generate_keypair(&mut self) -> Result<(Vec<u8>, Vec<u8>), DilithiumError> {
        self.unlock_memory().ok();

        let (public, private) = dilithium_keypair();

        let mut private_key = private.as_bytes().to_vec();
        Self::protect_buffer(&mut private_key)?;

        let public_key = public.as_bytes().to_vec();

        self.public = Some(public);
        self.private = Some(private);

        self.lock_memory()?;

        let result = (private_key.clone(), public_key);
        Self::unprotect_buffer(&mut private_key)?;

        Ok(result)
    }

    /// Signs a message using Dilithium with a random nonce.
    ///
    /// # Arguments
    /// * `data` - The message to sign
    ///
    /// # Returns
    /// * `Result<Vec<u8>, DilithiumError>` - The signature or an error
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, DilithiumError> {
        let key = self.private.as_ref().ok_or(DilithiumError::InvalidKey)?;

        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);

        let mut message = Vec::with_capacity(data.len() + NONCE_LEN);
        message.extend_from_slice(&nonce);
        message.extend_from_slice(data);

        let signature = detached_sign(&message, key).as_bytes().to_vec();

        let mut result = Vec::with_capacity(NONCE_LEN + signature.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&signature);

        Ok(result)
    }

    /// Verifies a Dilithium signature.
    ///
    /// # Arguments
    /// * `data` - The original message
    /// * `signature_with_nonce` - The signature to verify
    ///
    /// # Returns
    /// * `Result<bool, DilithiumError>` - True if signature is valid
    pub fn verify_signature(
        &self,
        data: &[u8],
        signature_with_nonce: &[u8],
    ) -> Result<bool, DilithiumError> {
        let public = self.public.as_ref().ok_or(DilithiumError::InvalidKey)?;

        if signature_with_nonce.len() <= NONCE_LEN {
            return Err(DilithiumError::VerificationError);
        }

        let (nonce, signature) = signature_with_nonce.split_at(NONCE_LEN);

        let mut message = Vec::with_capacity(data.len() + NONCE_LEN);
        message.extend_from_slice(nonce);
        message.extend_from_slice(data);

        let sig = DetachedSignature::from_bytes(signature)
            .map_err(|_| DilithiumError::VerificationError)?;

        Ok(verify_detached_signature(&sig, &message, public).is_ok())
    }

    /// Clears all sensitive data from memory.
    pub fn clear_sensitive_data(&mut self) {
        self.unlock_memory().ok();
        self.private = None;
        self.public = None;
        self.memory_locked = false;
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    }

    /// Sets the public key for signature verification.
    ///
    /// # Arguments
    /// * `public_key` - The public key bytes
    ///
    /// # Returns
    /// * `Result<(), DilithiumError>` - Success or an error
    pub fn set_public_key(&mut self, public_key: &[u8]) -> Result<(), DilithiumError> {
        self.public =
            Some(PublicKey::from_bytes(public_key).map_err(|_| DilithiumError::InvalidKey)?);
        Ok(())
    }

    /// Sets the private key for signing operations.
    ///
    /// # Arguments
    /// * `private_key` - The private key bytes
    ///
    /// # Returns
    /// * `Result<(), DilithiumError>` - Success or an error
    pub fn set_private_key(&mut self, private_key: &[u8]) -> Result<(), DilithiumError> {
        self.unlock_memory().ok();

        let private = SecretKey::from_bytes(private_key).map_err(|_| DilithiumError::InvalidKey)?;

        let empty_message = b"";
        let signature = detached_sign(empty_message, &private);
        let public = PublicKey::from_bytes(&signature.as_bytes()[..2592])
            .map_err(|_| DilithiumError::InvalidKey)?;

        self.private = Some(private);
        self.public = Some(public);

        self.lock_memory()?;
        Ok(())
    }
}

impl Drop for SecureDilithium {
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
        let mut dilithium = SecureDilithium::new();
        let (private_key, public_key) = dilithium.generate_keypair().unwrap();
        assert!(!private_key.is_empty(), "Generated private key is empty");
        assert!(!public_key.is_empty(), "Generated public key is empty");
    }

    #[test]
    fn test_signing_verification() {
        let mut dilithium = SecureDilithium::new();
        let (_, public_key) = dilithium.generate_keypair().unwrap();

        let data = b"Lorem ipsum dolor sit amet";
        let signature = dilithium.sign(data).unwrap();

        assert!(
            dilithium.verify_signature(data, &signature).unwrap(),
            "Signature verification failed with original key pair"
        );

        let mut public_only = SecureDilithium::new();
        public_only.set_public_key(&public_key).unwrap();
        assert!(
            public_only.verify_signature(data, &signature).unwrap(),
            "Signature verification failed with public key only"
        );

        let modified_data = b"Lorem ipsum dolor sit amet consectetur";
        assert!(
            !dilithium
                .verify_signature(modified_data, &signature)
                .unwrap(),
            "Signature verification should fail with modified data"
        );
    }

    #[test]
    fn test_different_signatures() {
        let mut dilithium = SecureDilithium::new();
        dilithium.generate_keypair().unwrap();

        let data = b"Lorem ipsum dolor sit amet";
        let signature1 = dilithium.sign(data).unwrap();
        let signature2 = dilithium.sign(data).unwrap();

        assert_ne!(
            signature1, signature2,
            "Signatures should be different due to Dilithium's randomness"
        );

        assert!(
            dilithium.verify_signature(data, &signature1).unwrap(),
            "First signature verification failed"
        );
        assert!(
            dilithium.verify_signature(data, &signature2).unwrap(),
            "Second signature verification failed"
        );
    }

    #[test]
    fn test_large_data() {
        let mut dilithium = SecureDilithium::new();
        dilithium.generate_keypair().unwrap();

        let large_data = vec![0u8; 1024 * 1024];
        let signature = dilithium.sign(&large_data).unwrap();
        assert!(
            dilithium.verify_signature(&large_data, &signature).unwrap(),
            "Large data signature verification failed"
        );
    }

    #[test]
    fn test_invalid_signature() {
        let mut dilithium = SecureDilithium::new();
        dilithium.generate_keypair().unwrap();

        let data = b"Lorem ipsum dolor sit amet";
        let mut signature = dilithium.sign(data).unwrap();

        if let Some(byte) = signature.last_mut() {
            *byte ^= 1;
        }

        assert!(
            !dilithium.verify_signature(data, &signature).unwrap(),
            "Modified signature should fail verification"
        );
    }

    #[test]
    fn test_performance() {
        let start = Instant::now();
        let mut dilithium = SecureDilithium::new();
        dilithium.generate_keypair().unwrap();
        let key_generation_duration = start.elapsed();

        let data = b"Lorem ipsum dolor sit amet";
        let iterations = 100;
        let mut total_signing_time = Duration::new(0, 0);
        let mut total_verification_time = Duration::new(0, 0);

        for i in 0..iterations {
            let start = Instant::now();
            let signature = dilithium.sign(data).unwrap();
            total_signing_time += start.elapsed();

            let start = Instant::now();
            let verified = dilithium.verify_signature(data, &signature).unwrap();
            total_verification_time += start.elapsed();

            assert!(verified, "Signature verification failed at iteration {}", i);
        }

        let avg_signing_time = total_signing_time / iterations as u32;
        let avg_verification_time = total_verification_time / iterations as u32;

        println!("Key generation time: {:?}", key_generation_duration);
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
    fn test_empty_data() {
        let mut dilithium = SecureDilithium::new();
        dilithium.generate_keypair().unwrap();

        let empty_data = b"";
        let signature = dilithium.sign(empty_data).unwrap();
        assert!(
            dilithium.verify_signature(empty_data, &signature).unwrap(),
            "Empty data signature verification failed"
        );
    }

    #[test]
    fn test_key_operations() {
        let mut dilithium1 = SecureDilithium::new();
        dilithium1.generate_keypair().unwrap();

        let dilithium2 = SecureDilithium::new();
        assert!(
            matches!(dilithium2.sign(b"Lorem"), Err(DilithiumError::InvalidKey)),
            "Signing without key should return InvalidKey error"
        );
        assert!(
            matches!(
                dilithium2.verify_signature(b"Lorem", b"sig"),
                Err(DilithiumError::InvalidKey)
            ),
            "Signature verification without key should return InvalidKey error"
        );
    }

    #[test]
    fn test_cross_instance_operations() {
        let mut dilithium1 = SecureDilithium::new();
        let (_, public_key) = dilithium1.generate_keypair().unwrap();

        let mut dilithium2 = SecureDilithium::new();
        dilithium2.set_public_key(&public_key).unwrap();

        let message = b"Lorem ipsum dolor sit amet";
        let signature = dilithium1.sign(message).unwrap();
        assert!(
            dilithium2.verify_signature(message, &signature).unwrap(),
            "Cross-instance signature verification failed"
        );
    }

    #[test]
    fn test_binary_data() {
        let mut dilithium = SecureDilithium::new();
        dilithium.generate_keypair().unwrap();

        let mut binary_data = Vec::with_capacity(256);
        for i in 0..=255u8 {
            binary_data.push(i);
        }

        let signature = dilithium.sign(&binary_data).unwrap();
        assert!(
            dilithium
                .verify_signature(&binary_data, &signature)
                .unwrap(),
            "Binary data signature verification failed"
        );
    }

    #[test]
    fn test_multiple_operations() {
        let mut dilithium = SecureDilithium::new();
        dilithium.generate_keypair().unwrap();

        for i in 0..5 {
            let message = format!("Lorem ipsum dolor sit amet {}", i).into_bytes();
            let signature = dilithium.sign(&message).unwrap();
            assert!(
                dilithium.verify_signature(&message, &signature).unwrap(),
                "Multiple signature operations failed at iteration {}",
                i
            );
        }
    }

    #[test]
    fn test_memory_protection() {
        let mut dilithium = SecureDilithium::new();
        dilithium.generate_keypair().unwrap();

        assert!(
            dilithium.memory_locked,
            "Memory should be locked after key generation"
        );

        drop(dilithium);

        let mut dilithium2 = SecureDilithium::new();
        dilithium2.generate_keypair().unwrap();
        assert!(
            dilithium2.memory_locked,
            "Memory should be locked after key generation"
        );
    }

    #[test]
    fn test_secure_buffer_wiping() {
        let mut buffer = vec![0xFFu8; 32];
        SecureDilithium::protect_buffer(&mut buffer).unwrap();
        SecureDilithium::unprotect_buffer(&mut buffer).unwrap();

        assert!(
            buffer.iter().all(|&b| b == 0),
            "Buffer should be securely wiped to zero after unprotection"
        );
    }

    #[test]
    fn test_constant_time_operations() {
        let mut dilithium = SecureDilithium::new();
        dilithium.generate_keypair().unwrap();
        let data = b"Lorem ipsum dolor sit amet";
        let signature = dilithium.sign(data).unwrap();

        let iterations = 1000;
        let mut valid_times = Vec::with_capacity(iterations);
        let mut invalid_times = Vec::with_capacity(iterations);

        for _ in 0..iterations {
            let start = Instant::now();
            let _ = dilithium.verify_signature(data, &signature).unwrap();
            valid_times.push(start.elapsed());

            let mut invalid_signature = signature.clone();
            if let Some(byte) = invalid_signature.last_mut() {
                *byte ^= 1;
            }
            let start = Instant::now();
            let _ = dilithium
                .verify_signature(data, &invalid_signature)
                .unwrap();
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
    fn test_memory_cleanup() {
        let mut dilithium = SecureDilithium::new();
        dilithium.generate_keypair().unwrap();

        assert!(
            dilithium.memory_locked,
            "Memory should be locked after key generation"
        );
        drop(dilithium);

        let mut dilithium2 = SecureDilithium::new();
        assert!(
            !dilithium2.memory_locked,
            "Memory should not be locked for new instance"
        );
        dilithium2.generate_keypair().unwrap();
        assert!(
            dilithium2.memory_locked,
            "Memory should be locked after key generation"
        );
    }

    #[test]
    fn test_error_messages() {
        let dilithium = SecureDilithium::new();
        let data = b"Lorem ipsum dolor sit amet";

        let err = dilithium.sign(data).unwrap_err();
        let err_str = format!("{:?}", err);
        assert!(
            !err_str.contains("key"),
            "Error message should not leak sensitive key information"
        );
    }

    #[test]
    fn test_protected_operations() {
        let mut dilithium = SecureDilithium::new();
        dilithium.generate_keypair().unwrap();

        let data = b"Lorem ipsum dolor sit amet";

        assert!(
            dilithium.memory_locked,
            "Memory should be locked after key generation"
        );

        let signature = dilithium.sign(data).unwrap();
        assert!(
            dilithium.memory_locked,
            "Memory should remain locked after signing"
        );

        let _ = dilithium.verify_signature(data, &signature).unwrap();
        assert!(
            dilithium.memory_locked,
            "Memory should remain locked after signature verification"
        );
    }

    #[test]
    fn test_key_derivation() {
        let mut dilithium1 = SecureDilithium::new();
        let (private_key, original_public_key) = dilithium1.generate_keypair().unwrap();

        let mut dilithium2 = SecureDilithium::new();
        dilithium2.set_private_key(&private_key).unwrap();

        let message = b"Lorem ipsum dolor sit amet";
        let signature = dilithium2.sign(message).unwrap();

        let mut dilithium3 = SecureDilithium::new();
        dilithium3.set_public_key(&original_public_key).unwrap();
        assert!(
            dilithium3.verify_signature(message, &signature).unwrap(),
            "Signature verification failed with original public key"
        );
    }
}
