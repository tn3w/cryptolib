# CryptoLib

> ⚠️ **SECURITY NOTICE**
>
> While this library implements secure cryptographic primitives following OWASP recommendations and best practices, it has **NOT YET** been thoroughly tested or audited by security professionals. The implementations use secure mechanics and follow cryptographic standards, but may contain undiscovered vulnerabilities.
>
> Security researchers are encouraged to test and analyze this software. If you discover any vulnerabilities or security issues, please report them through the [GitHub Issues](https://github.com/tn3w/cryptolib/issues).

A secure Rust implementation of cryptographic primitives following OWASP security recommendations and best practices. This library provides high-level implementations of AES, Argon2id, PBKDF2, RSA, and post-quantum cryptography (Kyber and Dilithium) with extensive security measures.

## Why

This library provides ready-to-use, secure implementations of common cryptographic primitives that you can directly copy and paste into your projects.

Instead of implementing these cryptographic primitives from scratch (which can be error-prone and risky), you can use these pre-made implementations as building blocks for your secure applications. This saves development time while ensuring proper security measures are in place.

## Security Implementation Recommendations

When choosing between the provided implementations, consider these important security recommendations:

### Post-Quantum vs Traditional Cryptography
- **Prefer Kyber over RSA** for encryption: Due to "Store Now, Decrypt Later" attacks, all current RSA-encrypted communications can be recorded and decrypted once quantum computers become available. Kyber provides quantum-resistant encryption that protects against future quantum computer attacks.
- **Choose Dilithium over RSA** for digital signatures: Similar to encryption, RSA signatures are vulnerable to quantum computing attacks. Dilithium provides quantum-resistant signatures that will remain secure in the post-quantum era.

### Password Hashing
- **Use Argon2id instead of PBKDF2** for password hashing: While both implementations are provided for compatibility, Argon2id is:
  - More secure against both GPU and ASIC attacks due to its memory-hard design
  - Faster than PBKDF2 while providing better security
  - The winner of the Password Hashing Competition and recommended by cryptography experts
  - More resistant to side-channel attacks through its hybrid design

## Security Features

All implementations share these security measures (when applicable):
- Memory protection using `mlock` and `madvise(MADV_DONTDUMP)`
- Secure memory wiping with volatile writes and memory fences
- Constant-time operations to prevent timing attacks
- Input validation and sanitization
- Comprehensive error handling without information leakage
- Protected key material in memory
- Side-channel attack mitigations
- Automatic cleanup using Drop trait

## Implementations

### Kyber Post-Quantum Key Encapsulation (KEM)
A lattice-based post-quantum key encapsulation mechanism.

**Parameters:**
- Kyber1024 security level (NIST Level 5 - highest security)
- Nonce size: 32 bytes (256 bits)
- Salt length: 32 bytes (256 bits)
- AES nonce length: 12 bytes (96 bits)
- PBKDF2 iterations: 100,000

**Security Features:**
- Post-quantum secure against quantum computer attacks (equivalent to AES-256 security level)
- Hybrid encryption with AES-256-GCM
- Secure key derivation using PBKDF2
- Protected shared secrets and key material
- Nonce generation for each operation

### Dilithium Post-Quantum Digital Signatures
A lattice-based post-quantum digital signature scheme.

**Parameters:**
- Dilithium5 security level (NIST Level 5 - highest security)
- Equivalent to AES-256 security level
- Signature size: 4595 bytes
- Public key size: 2592 bytes
- Private key size: 4864 bytes
- Nonce size: 32 bytes (256 bits)

**Security Features:**
- Post-quantum secure digital signatures (highest security level)
- Protected private key material with memory locking
- Nonce generation for each signature
- Memory protection for sensitive data
- Constant-time operations to prevent timing attacks
- Automatic cleanup of sensitive data

### Argon2id Password Hashing
The primary recommended password hashing algorithm.

**Parameters (OWASP Recommended):**
- Memory: 12 MiB (12,288 KiB)
- Iterations: 3
- Parallelism: 1
- Salt length: 32 bytes (256 bits)
- Hash length: 32 bytes (256 bits)

**Security Features:**
- Memory-hard algorithm resistant to GPU/ASIC attacks
- Hybrid approach combining Argon2d and Argon2i
- Protection against both timing and tradeoff attacks
- Unique salt generation for each hash
- Password length validation (8-1024 bytes)

### AES-256-GCM Encryption

**Parameters (OWASP Recommended):**
- Key size: 256 bits
- GCM mode for authenticated encryption
- Nonce size: 96 bits
- Tag size: 128 bits
- Salt size: 256 bits
- PBKDF2 iterations for key derivation: 100,000

**Security Features:**
- Authenticated encryption with associated data (AEAD)
- Secure key derivation using PBKDF2-HMAC-SHA256
- Random nonce generation for each encryption
- Integrity verification with authentication tags
- Secret length validation (16-1024 bytes)

### PBKDF2 Password Hashing
A legacy-compatible password hashing implementation.

**Parameters (OWASP Recommended):**
- Iterations: 600,000
- Salt length: 32 bytes (256 bits)
- Hash length: 32 bytes (256 bits)
- HMAC-SHA256 as PRF

**Security Features:**
- High iteration count to increase computational cost
- Unique salt generation for each hash
- Password length validation (8-1024 bytes)
- Constant-time comparison for verification

### RSA Encryption and Signing

**Parameters:**
- Key size: 2048 bits (minimum)
- Public exponent: 65537
- Padding: OAEP with SHA-256 for encryption
- PSS padding with SHA-256 for signatures

**Security Features:**
- Secure key generation with proper prime testing
- OAEP padding for encryption security
- PSS padding for signature security
- Key zeroization after use
- Protected key material in memory

## Usage Examples

### Kyber Post-Quantum Encryption
```rust
// Create a new instance and generate key pair
let mut kyber = SecureKyber::new();
let (private_key, public_key) = kyber.generate_keypair()?;

// Create instances from exported keys
// For encryption only (public key)
let encryptor = SecureKyber::from_public_key(&public_key)?;

// For decryption (private key)
let mut decryptor = SecureKyber::new();
decryptor.set_private_key(&private_key)?;

// Encrypt data using public key instance
let data = b"sensitive data";
let encrypted = encryptor.encrypt(data)?;

// Decrypt data using private key instance
let decrypted = decryptor.decrypt(&encrypted)?;
assert_eq!(data, &decrypted[..]);

// Key encapsulation with separate instances
let (ciphertext, shared_secret1) = encryptor.encapsulate()?;
let shared_secret2 = decryptor.decapsulate(&ciphertext)?;
assert_eq!(shared_secret1, shared_secret2);

// Clear sensitive data when done
decryptor.clear_sensitive_data();
```

### Dilithium Post-Quantum Signatures
```rust
let mut dilithium = SecureDilithium::new();

// Generate new key pair
let (private_key, public_key) = dilithium.generate_keypair()?;

// Export keys for storage
// The keys are returned as byte arrays that can be safely stored
let exported_private_key = private_key.clone();
let exported_public_key = public_key.clone();

// Create a new instance with existing private key
let mut signer = SecureDilithium::new();
signer.set_private_key(&exported_private_key)?;

// Create a new instance with only public key for verification
let mut verifier = SecureDilithium::new();
verifier.set_public_key(&exported_public_key)?;

// Sign data with private key instance
let data = b"message to sign";
let signature = signer.sign(data)?;

// Verify signature with public key instance
let is_valid = verifier.verify_signature(data, &signature)?;
assert!(is_valid);

// Clear sensitive data when done
signer.clear_sensitive_data();
```

### Argon2id Password Hashing
```rust
// Create a new hasher instance
let hasher = SecureArgon2id::new();
let password = b"my_secure_password";

// Hash password with unique salt
let hash = hasher.hash_password(password)?;

// Verify password against stored hash
let is_valid = hasher.verify_password(password, &hash)?;
```

### AES-256-GCM Encryption
```rust
// Create a new encryptor with secret key
let encryptor = SecureAES::new(secret)?;
let data = b"sensitive data";

// Encrypt data with random salt and nonce
let encrypted = encryptor.encrypt(data)?;

// Decrypt data and verify integrity
let decrypted = encryptor.decrypt(&encrypted)?;
```

### PBKDF2 Password Hashing
```rust
// Create a new hasher instance
let hasher = SecurePbkdf2::new();
let password = b"my_secure_password";

// Hash password with unique salt
let hash = hasher.hash_password(password)?;

// Verify password against stored hash
let is_valid = hasher.verify_password(password, &hash)?;
```

### RSA Encryption and Signing
```rust
// Create a new instance and generate key pair
let mut rsa = SecureRSA::new();
let (private_key, public_key) = rsa.generate_keypair()?;

// Encrypt data using public key
let data = b"sensitive data";
let encrypted = rsa.encrypt(data)?;

// Decrypt data using private key
let decrypted = rsa.decrypt(&encrypted)?;

// Sign data using private key
let signature = rsa.sign(data)?;

// Verify signature using public key
let is_valid = rsa.verify_signature(data, &signature)?;
```

## Running Examples

The library includes several example programs demonstrating the usage of each cryptographic primitive. You can run them using cargo:

```bash
# Run AES-256-GCM encryption example
cargo run --example aes --release

# Run RSA encryption and signing example
cargo run --example rsa --release

# Run Kyber post-quantum encryption example
cargo run --example kyber --release

# Run Dilithium post-quantum signature example
cargo run --example dilithium --release

# Run PBKDF2 password hashing example
cargo run --example pbkdf2 --release

# Run Argon2id password hashing example
cargo run --example argon2id --release
```

## Testing

Each implementation includes comprehensive tests.

## Dependencies

- `argon2`: Password hashing
- `ring`: Cryptographic primitives
- `rand`: Secure random number generation
- `rsa`: RSA implementation
- `pbkdf2`: Key derivation
- `constant_time_eq`: Constant-time comparison
- `libc`: Memory protection
- `pqcrypto-kyber`: Kyber post-quantum KEM
- `pqcrypto-dilithium`: Dilithium post-quantum signatures
- `pqcrypto-traits`: Common traits for post-quantum cryptography

## License

Copyright 2025, TN3W

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Security References

For detailed understanding of the implemented algorithms and their security considerations:

### Post-Quantum Cryptography
- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography) - Official NIST documentation on post-quantum cryptography standards
- [Kyber: Algorithm Specifications and Supporting Documentation](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf) - Detailed technical specification of the Kyber algorithm
- [Dilithium: Algorithm Specifications and Supporting Documentation](https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf) - Complete specification of the Dilithium signature scheme

### Password Hashing
- [Argon2: Memory-Hard Function for Password Hashing and Proof-of-Work Applications](https://password-hashing.net/argon2-specs.pdf) - Official Argon2 specification paper
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) - Best practices for secure password storage
- [Password Hashing Competition](https://password-hashing.net/) - Details on why Argon2 was selected as the winner

### Symmetric Encryption
- [NIST AES Resources](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/archived-crypto-projects/aes-development) - Comprehensive documentation on AES
- [NIST SP 800-38D: Galois/Counter Mode](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) - Detailed specification of GCM mode of operation

### Key Derivation and RSA
- [NIST SP 800-132: PBKDF Recommendation](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf) - Guidelines for password-based key derivation
- [NIST SP 800-56B Rev. 2: RSA-Based Key-Establishment](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br2.pdf) - RSA key establishment schemes
- [RFC 8017 - PKCS #1 v2.2: RSA Cryptography Specifications](https://datatracker.ietf.org/doc/html/rfc8017) - Standard RSA implementations and padding schemes

### Side-Channel Attack Prevention
- [Constant-Time Cryptography Guidelines](https://github.com/veorq/cryptocoding) - Best practices for implementing constant-time operations
- [Side-Channel Attacks on Post-Quantum Cryptography](https://eprint.iacr.org/2016/461.pdf) - Analysis of side-channel considerations in post-quantum algorithms

### Memory Protection
- [Linux mlock Manual](https://man7.org/linux/man-pages/man2/mlock.2.html) - Documentation for secure memory locking
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) - Best practices for protecting cryptographic material 
