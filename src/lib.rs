//! A secure high-level implementation of cryptographic primitives with post-quantum support.
//!
//! This library provides implementations of various cryptographic algorithms following
//! OWASP security recommendations and best practices. It includes both traditional
//! and post-quantum cryptographic primitives.

mod aes;
mod argon2id;
mod dilithium;
mod kyber;
mod pbkdf2;
mod rsa;

pub use crate::{
    aes::SecureAES,
    argon2id::SecureArgon2id,
    dilithium::SecureDilithium,
    kyber::SecureKyber,
    pbkdf2::SecurePbkdf2,
    rsa::SecureRSA,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_availability() {
        let _aes = SecureAES::new(&[0u8; 32]).unwrap();
        let _argon2 = SecureArgon2id::new();
        let _dilithium = SecureDilithium::new();
        let _kyber = SecureKyber::new();
        let _pbkdf2 = SecurePbkdf2::new();
        let _rsa = SecureRSA::new();
    }
}
