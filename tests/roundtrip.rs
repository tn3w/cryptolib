use cryptolib::{
    Error, SecureAES, SecureArgon2id, SecureMlDsa, SecureMlKem, SecurePbkdf2, SecureRSA,
};

#[test]
fn aes_roundtrip_and_tampering() {
    let aes = SecureAES::new(b"sixteen byte key").unwrap();
    let mut encrypted = aes.encrypt(b"secret").unwrap();
    assert_eq!(aes.decrypt(&encrypted).unwrap(), b"secret");
    assert_ne!(aes.encrypt(b"secret").unwrap(), encrypted);

    *encrypted.last_mut().unwrap() ^= 1;
    assert_eq!(aes.decrypt(&encrypted), Err(Error::Decryption));
    assert_eq!(aes.decrypt(&[0; 10]), Err(Error::InvalidInput));
    assert!(SecureAES::new(b"short").is_err());
}

#[test]
fn aes_wrong_secret_fails() {
    let encrypted = SecureAES::new(b"first secret key")
        .unwrap()
        .encrypt(b"")
        .unwrap();
    let other = SecureAES::new(b"other secret key").unwrap();
    assert_eq!(other.decrypt(&encrypted), Err(Error::Decryption));
}

#[test]
fn argon2id_hash_and_verify() {
    let hasher = SecureArgon2id::new();
    let hash = hasher.hash_password(b"correct horse").unwrap();
    assert!(hasher.verify_password(b"correct horse", &hash).unwrap());
    assert!(!hasher.verify_password(b"wrong horse!", &hash).unwrap());
    assert_ne!(hasher.hash_password(b"correct horse").unwrap(), hash);
    assert_eq!(hasher.hash_password(b"short"), Err(Error::InvalidInput));
    assert_eq!(
        hasher.verify_password(b"correct horse", b"x"),
        Err(Error::InvalidInput)
    );
}

#[test]
fn pbkdf2_hash_and_verify() {
    let hasher = SecurePbkdf2::new();
    let hash = hasher.hash_password(b"correct horse").unwrap();
    assert!(hasher.verify_password(b"correct horse", &hash).unwrap());
    assert!(!hasher.verify_password(b"wrong horse!", &hash).unwrap());
}

#[test]
fn rsa_encrypt_and_sign_with_exported_keys() {
    let (private_pem, public_pem) = SecureRSA::new().generate_keypair().unwrap();
    let mut sender = SecureRSA::new();
    sender.set_public_key(&public_pem).unwrap();
    let mut receiver = SecureRSA::new();
    receiver.set_private_key(&private_pem).unwrap();

    let encrypted = sender.encrypt(b"hybrid message").unwrap();
    assert_eq!(receiver.decrypt(&encrypted).unwrap(), b"hybrid message");
    assert_eq!(sender.decrypt(&encrypted), Err(Error::MissingKey));

    let signature = receiver.sign(b"document").unwrap();
    assert!(sender.verify_signature(b"document", &signature).unwrap());
    assert!(!sender.verify_signature(b"tampered", &signature).unwrap());
}

#[test]
fn mlkem_encrypt_and_encapsulate() {
    let (secret_key, public_key) = SecureMlKem::new().generate_keypair();
    let sender = SecureMlKem::from_public_key(&public_key).unwrap();
    let mut receiver = SecureMlKem::new();
    receiver.set_private_key(&secret_key).unwrap();

    let encrypted = sender.encrypt(b"post-quantum").unwrap();
    assert_eq!(receiver.decrypt(&encrypted).unwrap(), b"post-quantum");

    let (ciphertext, shared_secret) = sender.encapsulate().unwrap();
    assert_eq!(receiver.decapsulate(&ciphertext).unwrap(), shared_secret);
    assert_eq!(receiver.decrypt(&encrypted[..40]), Err(Error::InvalidInput));
}

#[test]
fn mldsa_sign_and_verify() {
    let (secret_key, public_key) = SecureMlDsa::new().generate_keypair();
    let mut signer = SecureMlDsa::new();
    signer.set_private_key(&secret_key).unwrap();
    let mut verifier = SecureMlDsa::new();
    verifier.set_public_key(&public_key).unwrap();

    let signature = signer.sign(b"document").unwrap();
    assert!(verifier.verify_signature(b"document", &signature).unwrap());
    assert!(!verifier.verify_signature(b"tampered", &signature).unwrap());
    assert!(!verifier.verify_signature(b"document", b"garbage").unwrap());
}
