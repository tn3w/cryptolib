# cryptolib

High-level Rust wrappers for common cryptography with safe defaults:
AES-256-GCM, Argon2id, PBKDF2, RSA, ML-KEM and ML-DSA.

> Not audited. Built on audited or widely reviewed crates (`ring`, `argon2`, `rsa`,
> PQClean via `pqcrypto`), but the composition has not been reviewed.

```toml
[dependencies]
cryptolib = { git = "https://github.com/tn3w/cryptolib" }
```

## Usage

```rust
use cryptolib::*;

let aes = SecureAES::new(b"at least 16 bytes")?;
let decrypted = aes.decrypt(&aes.encrypt(b"data")?)?;

let hasher = SecureArgon2id::new();
let hash = hasher.hash_password(b"password")?;
assert!(hasher.verify_password(b"password", &hash)?);

let (secret_key, public_key) = SecureMlKem::new().generate_keypair();
let encrypted = SecureMlKem::from_public_key(&public_key)?.encrypt(b"data")?;
let mut receiver = SecureMlKem::new();
receiver.set_private_key(&secret_key)?;
let decrypted = receiver.decrypt(&encrypted)?;

let (secret_key, public_key) = SecureMlDsa::new().generate_keypair();
let mut signer = SecureMlDsa::new();
signer.set_private_key(&secret_key)?;
let signature = signer.sign(b"document")?;
let mut verifier = SecureMlDsa::new();
verifier.set_public_key(&public_key)?;
assert!(verifier.verify_signature(b"document", &signature)?);

let mut rsa = SecureRSA::new();
let (private_pem, public_pem) = rsa.generate_keypair()?;
let signature = rsa.sign(b"document")?;
assert!(rsa.verify_signature(b"document", &signature)?);
```

All functions return `cryptolib::Result<T>` with `Error::{InvalidInput, InvalidKey,
MissingKey, Encryption, Decryption}`. Secret outputs are `Zeroizing` and wiped on drop.

## Primitives

| Type | Algorithm | Output format |
| --- | --- | --- |
| `SecureAES` | AES-256-GCM, key from PBKDF2-HMAC-SHA256 (600,000 iterations) | `salt 32 · nonce 12 · ciphertext · tag 16` |
| `SecureArgon2id` | Argon2id, 19 MiB, 2 iterations, 1 lane | `hash 32 · salt 32` |
| `SecurePbkdf2` | PBKDF2-HMAC-SHA256, 600,000 iterations | `hash 32 · salt 32` |
| `SecureRSA` | RSA-4096, OAEP-SHA256 wrapping an AES-256-GCM key; PSS-SHA256 signatures; PKCS#8/SPKI PEM keys | `key length 4 (BE) · wrapped key · nonce · ciphertext · tag` |
| `SecureMlKem` | ML-KEM-1024 (FIPS 203), HKDF-SHA256 → AES-256-GCM | `salt 32 · KEM ciphertext 1568 · nonce · ciphertext · tag` |
| `SecureMlDsa` | ML-DSA-87 (FIPS 204), detached signatures | raw signature |

Parameters follow the
[OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
Passwords must be 8–1024 bytes, AES secrets 16–1024 bytes. Password verification is
constant-time.

## Recommendations

- Prefer ML-KEM over RSA for encryption and ML-DSA over RSA for signatures
  ("store now, decrypt later").
- Prefer Argon2id over PBKDF2 for passwords.
- `rsa` has a known timing side channel in decryption
  ([RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071)); avoid RSA
  decryption where attackers can measure timing.

## Development

```bash
cargo test --release
```

## License

[Apache-2.0](LICENSE)
