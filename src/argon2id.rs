use argon2::{
    password_hash::{PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params, Version,
};
use libc::{c_void, madvise, mlock, munlock, MADV_DONTDUMP};
use rand::{rngs::OsRng, Rng};
use std::{ptr, sync::atomic::Ordering};

// OWASP recommended parameters
// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
const MEMORY_SIZE: u32 = 12_288; // 12 MiB
const ITERATIONS: u32 = 3;
const PARALLELISM: u32 = 1;
const SALT_LEN: usize = 32; // 256 bits
const HASH_LEN: usize = 32; // 256 bits
const MIN_PASSWORD_LEN: usize = 8;
const MAX_PASSWORD_LEN: usize = 1024;

#[derive(Debug)]
pub enum Argon2idError {
    HashingError,
    ValidationError,
    MemoryProtectionError,
    InvalidInput,
}

impl std::fmt::Display for Argon2idError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HashingError => write!(f, "Password hashing failed"),
            Self::ValidationError => write!(f, "Input validation failed"),
            Self::MemoryProtectionError => write!(f, "Memory protection failed"),
            Self::InvalidInput => write!(f, "Invalid input provided"),
        }
    }
}

/// A secure Argon2id password hashing implementation with memory protection.
pub struct SecureArgon2id {
    argon2: Argon2<'static>,
}

impl SecureArgon2id {
    /// Creates a new Argon2id password hasher with OWASP recommended parameters.
    ///
    /// # Parameters
    /// * Memory: 12 MiB (12,288 KiB)
    /// * Iterations: 3
    /// * Parallelism: 1
    /// * Salt length: 32 bytes (256 bits)
    /// * Hash length: 32 bytes (256 bits)
    pub fn new() -> Self {
        let params = Params::new(MEMORY_SIZE, ITERATIONS, PARALLELISM, Some(HASH_LEN)).unwrap();

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

        Self { argon2 }
    }

    fn secure_zero(buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            unsafe { ptr::write_volatile(byte, 0) };
        }
        std::sync::atomic::fence(Ordering::SeqCst);
    }

    fn protect_buffer(buf: &mut [u8]) -> Result<(), Argon2idError> {
        let ptr = buf.as_ptr() as *const c_void;
        let size = buf.len();

        unsafe {
            let _ = mlock(ptr, size);
            let _ = madvise(ptr as *mut c_void, size, MADV_DONTDUMP);
        }
        Ok(())
    }

    fn unprotect_buffer(buf: &mut [u8]) -> Result<(), Argon2idError> {
        let ptr = buf.as_ptr() as *const c_void;
        let size = buf.len();
        unsafe {
            let _ = munlock(ptr, size);
        }
        Self::secure_zero(buf);
        Ok(())
    }

    fn validate_password(password: &[u8]) -> Result<(), Argon2idError> {
        if password.len() < MIN_PASSWORD_LEN || password.len() > MAX_PASSWORD_LEN {
            return Err(Argon2idError::ValidationError);
        }
        Ok(())
    }

    /// Hashes a password using Argon2id with a random salt.
    ///
    /// # Arguments
    /// * `password` - The password to hash (8-1024 bytes)
    ///
    /// # Returns
    /// * `Result<Vec<u8>, Argon2idError>` - The encoded hash string or an error
    pub fn hash_password(&self, password: &[u8]) -> Result<Vec<u8>, Argon2idError> {
        Self::validate_password(password)?;

        let mut salt = [0u8; SALT_LEN];
        OsRng.fill(&mut salt);

        let mut protected_salt = salt.to_vec();
        Self::protect_buffer(&mut protected_salt)?;

        let salt_string =
            SaltString::encode_b64(&protected_salt).map_err(|_| Argon2idError::HashingError)?;

        let mut hash = self
            .argon2
            .hash_password(password, &salt_string)
            .map_err(|_| Argon2idError::HashingError)?
            .to_string()
            .into_bytes();

        Self::protect_buffer(&mut hash)?;

        Self::unprotect_buffer(&mut protected_salt)?;

        Ok(hash)
    }

    /// Verifies a password against a stored Argon2id hash.
    ///
    /// # Arguments
    /// * `password` - The password to verify (8-1024 bytes)
    /// * `stored_hash` - The stored hash to verify against
    ///
    /// # Returns
    /// * `Result<bool, Argon2idError>` - True if password matches, false if it doesn't
    pub fn verify_password(
        &self,
        password: &[u8],
        stored_hash: &[u8],
    ) -> Result<bool, Argon2idError> {
        Self::validate_password(password)?;

        if stored_hash.is_empty() {
            return Err(Argon2idError::ValidationError);
        }

        let hash_str =
            std::str::from_utf8(stored_hash).map_err(|_| Argon2idError::ValidationError)?;

        let parsed_hash = argon2::password_hash::PasswordHash::new(hash_str)
            .map_err(|_| Argon2idError::ValidationError)?;

        Ok(self.argon2.verify_password(password, &parsed_hash).is_ok())
    }
}

impl Drop for SecureArgon2id {
    fn drop(&mut self) {
        let ptr = &self.argon2 as *const _ as *mut u8;
        let size = std::mem::size_of_val(&self.argon2);
        unsafe {
            for i in 0..size {
                ptr::write_volatile(ptr.add(i), 0);
            }
        }
        std::sync::atomic::fence(Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn test_hash_and_verify_valid_password() {
        let hasher = SecureArgon2id::new();
        let password = b"correct_horse_battery_staple";

        let hash = hasher.hash_password(password).unwrap();
        assert!(
            hasher.verify_password(password, &hash).unwrap(),
            "Password verification failed for valid password"
        );
    }

    #[test]
    fn test_verify_wrong_password() {
        let hasher = SecureArgon2id::new();
        let password = b"correct_horse_battery_staple";
        let wrong_password = b"wrong_password_guess";

        let hash = hasher.hash_password(password).unwrap();
        assert!(
            !hasher.verify_password(wrong_password, &hash).unwrap(),
            "Wrong password should not verify successfully"
        );
    }

    #[test]
    fn test_different_hashes_for_same_password() {
        let hasher = SecureArgon2id::new();
        let password = b"correct_horse_battery_staple";

        let hash1 = hasher.hash_password(password).unwrap();
        let hash2 = hasher.hash_password(password).unwrap();

        assert_ne!(
            hash1, hash2,
            "Same password should produce different hashes due to random salt"
        );
    }

    #[test]
    fn test_invalid_stored_hash() {
        let hasher = SecureArgon2id::new();
        let password = b"test_password_123";
        let invalid_hash = b"invalid_hash_format";

        assert!(
            matches!(
                hasher.verify_password(password, invalid_hash),
                Err(Argon2idError::ValidationError)
            ),
            "Invalid hash format should return ValidationError"
        );
    }

    #[test]
    fn test_password_length_validation() {
        let hasher = SecureArgon2id::new();
        let short_password = b"short";
        let long_password = vec![b'a'; MAX_PASSWORD_LEN + 1];

        assert!(
            matches!(
                hasher.hash_password(short_password),
                Err(Argon2idError::ValidationError)
            ),
            "Short password should be rejected"
        );
        assert!(
            matches!(
                hasher.hash_password(&long_password),
                Err(Argon2idError::ValidationError)
            ),
            "Too long password should be rejected"
        );
    }

    #[test]
    fn test_memory_protection() {
        let mut buffer = vec![0xFFu8; 32];
        SecureArgon2id::protect_buffer(&mut buffer).unwrap();
        SecureArgon2id::unprotect_buffer(&mut buffer).unwrap();

        assert!(
            buffer.iter().all(|&b| b == 0),
            "Buffer should be securely wiped after unprotection"
        );
    }

    #[test]
    fn test_constant_time_verification() {
        let hasher = SecureArgon2id::new();
        let password = b"correct_horse_battery_staple";
        let hash = hasher.hash_password(password).unwrap();

        let iterations = 100;
        let mut valid_times = Vec::with_capacity(iterations);
        let mut invalid_times = Vec::with_capacity(iterations);

        for _ in 0..10 {
            let _ = hasher.verify_password(password, &hash);
        }

        for _ in 0..iterations {
            let start = Instant::now();
            let _ = hasher.verify_password(password, &hash);
            valid_times.push(start.elapsed());

            let wrong_password = b"wrong_password_guess";
            let start = Instant::now();
            let _ = hasher.verify_password(wrong_password, &hash);
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

        assert!(time_diff < 1.5, "Timing difference between valid and invalid password verification is too large: {:.2}x", time_diff);
    }

    #[test]
    fn test_error_messages() {
        let hasher = SecureArgon2id::new();
        let password = b"test_password";
        let invalid_hash = b"invalid";

        let err = hasher.verify_password(password, invalid_hash).unwrap_err();
        let err_str = format!("{:?}", err);
        assert!(
            !err_str.contains("password"),
            "Error message should not leak password information"
        );
    }

    #[test]
    fn test_salt_uniqueness() {
        let hasher = SecureArgon2id::new();
        let password = b"test_password_123";

        let mut salts = Vec::new();
        for _ in 0..100 {
            let hash = hasher.hash_password(password).unwrap();
            let hash_str = String::from_utf8_lossy(&hash);
            let salt = hash_str.split('$').nth(4).unwrap();
            assert!(
                !salts.contains(&salt.to_string()),
                "Salt reuse detected - each hash should have a unique salt"
            );
            salts.push(salt.to_string());
        }
    }

    #[test]
    fn test_binary_password_handling() {
        let hasher = SecureArgon2id::new();
        let binary_password = (0..32u8).collect::<Vec<_>>();

        let hash = hasher.hash_password(&binary_password).unwrap();
        assert!(
            hasher.verify_password(&binary_password, &hash).unwrap(),
            "Should handle binary passwords correctly"
        );
    }

    #[test]
    fn test_performance() {
        let data = b"Lorem ipsum dolor sit amet";

        let start = Instant::now();
        let hasher = SecureArgon2id::new();
        let setup_time = start.elapsed();

        let iterations = 100;
        let mut total_hash_time = Duration::new(0, 0);
        let mut total_verify_time = Duration::new(0, 0);

        for i in 0..iterations {
            let start = Instant::now();
            let hash = hasher.hash_password(data).unwrap();
            total_hash_time += start.elapsed();

            let start = Instant::now();
            let verified = hasher.verify_password(data, &hash).unwrap();
            total_verify_time += start.elapsed();

            assert!(verified, "Password verification failed at iteration {}", i);
        }

        let avg_hash_time = total_hash_time / iterations as u32;
        let avg_verify_time = total_verify_time / iterations as u32;

        println!("Setup time: {:?}", setup_time);
        println!(
            "Average hash time over {} iterations: {:?}",
            iterations, avg_hash_time
        );
        println!(
            "Average verify time over {} iterations: {:?}",
            iterations, avg_verify_time
        );
    }
}
