use libc::{c_void, madvise, mlock, munlock, MADV_DONTDUMP};
use pbkdf2::{
    password_hash::{PasswordHasher, PasswordVerifier, SaltString},
    Pbkdf2,
};
use rand::{rngs::OsRng, Rng};
use std::{ptr, sync::atomic::Ordering};

// OWASP recommended parameters
// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
const ITERATIONS: u32 = 600_000;
const SALT_LEN: usize = 32; // 256 bits
const HASH_LEN: usize = 32; // 256 bits
const MIN_PASSWORD_LEN: usize = 8;
const MAX_PASSWORD_LEN: usize = 1024;

#[derive(Debug)]
pub enum Pbkdf2Error {
    HashingError,
    ValidationError,
    MemoryProtectionError,
    InvalidInput,
}

/// A secure PBKDF2 password hashing implementation with memory protection.
pub struct SecurePbkdf2 {
    pbkdf2: Pbkdf2,
}

impl SecurePbkdf2 {
    /// Creates a new PBKDF2 password hasher with OWASP recommended parameters.
    ///
    /// # Parameters
    /// * Iterations: 600,000
    /// * Salt length: 32 bytes (256 bits)
    /// * Hash length: 32 bytes (256 bits)
    /// * HMAC-SHA256 as PRF
    pub fn new() -> Self {
        Self { pbkdf2: Pbkdf2 }
    }

    fn secure_zero(buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            unsafe { ptr::write_volatile(byte, 0) };
        }
        std::sync::atomic::fence(Ordering::SeqCst);
    }

    fn protect_buffer(buf: &mut [u8]) -> Result<(), Pbkdf2Error> {
        let ptr = buf.as_ptr() as *const c_void;
        let size = buf.len();

        unsafe {
            let _ = mlock(ptr, size);
            let _ = madvise(ptr as *mut c_void, size, MADV_DONTDUMP);
        }
        Ok(())
    }

    fn unprotect_buffer(buf: &mut [u8]) -> Result<(), Pbkdf2Error> {
        let ptr = buf.as_ptr() as *const c_void;
        let size = buf.len();
        unsafe {
            let _ = munlock(ptr, size);
        }
        Self::secure_zero(buf);
        Ok(())
    }

    fn validate_password(password: &[u8]) -> Result<(), Pbkdf2Error> {
        if password.len() < MIN_PASSWORD_LEN || password.len() > MAX_PASSWORD_LEN {
            return Err(Pbkdf2Error::ValidationError);
        }
        Ok(())
    }

    /// Hashes a password using PBKDF2 with a random salt.
    ///
    /// # Arguments
    /// * `password` - The password to hash (8-1024 bytes)
    ///
    /// # Returns
    /// * `Result<Vec<u8>, Pbkdf2Error>` - The encoded hash string or an error
    pub fn hash_password(&self, password: &[u8]) -> Result<Vec<u8>, Pbkdf2Error> {
        Self::validate_password(password)?;

        let mut salt = [0u8; SALT_LEN];
        OsRng.fill(&mut salt);

        let mut protected_salt = salt.to_vec();
        Self::protect_buffer(&mut protected_salt)?;

        let salt_string =
            SaltString::encode_b64(&protected_salt).map_err(|_| Pbkdf2Error::HashingError)?;

        let mut hash = self
            .pbkdf2
            .hash_password_customized(
                password,
                None,
                None,
                pbkdf2::Params {
                    rounds: ITERATIONS,
                    output_length: HASH_LEN,
                },
                &salt_string,
            )
            .map_err(|_| Pbkdf2Error::HashingError)?
            .to_string()
            .into_bytes();

        Self::protect_buffer(&mut hash)?;
        Self::unprotect_buffer(&mut protected_salt)?;

        Ok(hash)
    }

    /// Verifies a password against a stored PBKDF2 hash.
    ///
    /// # Arguments
    /// * `password` - The password to verify (8-1024 bytes)
    /// * `stored_hash` - The stored hash to verify against
    ///
    /// # Returns
    /// * `Result<bool, Pbkdf2Error>` - True if password matches, false if it doesn't
    pub fn verify_password(
        &self,
        password: &[u8],
        stored_hash: &[u8],
    ) -> Result<bool, Pbkdf2Error> {
        Self::validate_password(password)?;

        if stored_hash.is_empty() {
            return Err(Pbkdf2Error::ValidationError);
        }

        let hash_str =
            std::str::from_utf8(stored_hash).map_err(|_| Pbkdf2Error::ValidationError)?;

        let parsed_hash = pbkdf2::password_hash::PasswordHash::new(hash_str)
            .map_err(|_| Pbkdf2Error::ValidationError)?;

        Ok(self.pbkdf2.verify_password(password, &parsed_hash).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn test_hash_and_verify_valid_password() {
        let hasher = SecurePbkdf2::new();
        let password = b"correct_horse_battery_staple";

        let hash = hasher.hash_password(password).unwrap();
        assert!(
            hasher.verify_password(password, &hash).unwrap(),
            "Password verification failed for valid password"
        );
    }

    #[test]
    fn test_verify_wrong_password() {
        let hasher = SecurePbkdf2::new();
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
        let hasher = SecurePbkdf2::new();
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
        let hasher = SecurePbkdf2::new();
        let password = b"test_password_123";
        let invalid_hash = b"invalid_hash_format";

        assert!(
            matches!(
                hasher.verify_password(password, invalid_hash),
                Err(Pbkdf2Error::ValidationError)
            ),
            "Invalid hash format should return ValidationError"
        );
    }

    #[test]
    fn test_password_length_validation() {
        let hasher = SecurePbkdf2::new();
        let short_password = b"short";
        let long_password = vec![b'a'; MAX_PASSWORD_LEN + 1];

        assert!(
            matches!(
                hasher.hash_password(short_password),
                Err(Pbkdf2Error::ValidationError)
            ),
            "Short password should be rejected"
        );
        assert!(
            matches!(
                hasher.hash_password(&long_password),
                Err(Pbkdf2Error::ValidationError)
            ),
            "Too long password should be rejected"
        );
    }

    #[test]
    fn test_memory_protection() {
        let mut buffer = vec![0xFFu8; 32];
        SecurePbkdf2::protect_buffer(&mut buffer).unwrap();
        SecurePbkdf2::unprotect_buffer(&mut buffer).unwrap();

        assert!(
            buffer.iter().all(|&b| b == 0),
            "Buffer should be securely wiped after unprotection"
        );
    }

    #[test]
    fn test_constant_time_verification() {
        let hasher = SecurePbkdf2::new();
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
    fn test_binary_password_handling() {
        let hasher = SecurePbkdf2::new();
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
        let hasher = SecurePbkdf2::new();
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
