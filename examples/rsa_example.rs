use cryptolib::SecureRSA;
use std::time::Instant;

fn main() {
    println!("\n=== RSA Example ===");
    println!();

    let start = Instant::now();
    let mut rsa = SecureRSA::new();
    match rsa.generate_keypair() {
        Ok((private_key, public_key)) => {
            let key_gen_time = start.elapsed();
            println!("=== RSA Key Generation ===");
            println!("Generation time: {:?}", key_gen_time);

            println!("\nPrivate Key ({} bytes):", private_key.len());
            println!("PEM format:");
            println!("{}", String::from_utf8_lossy(&private_key));

            println!("Hex format:");
            for (i, byte) in private_key.iter().enumerate() {
                print!("{:02x}", byte);
                if (i + 1) % 32 == 0 {
                    println!();
                }
            }
            println!();

            println!("\nPublic Key ({} bytes):", public_key.len());
            println!("PEM format:");
            println!("{}", String::from_utf8_lossy(&public_key));

            println!("Hex format:");
            for (i, byte) in public_key.iter().enumerate() {
                print!("{:02x}", byte);
                if (i + 1) % 32 == 0 {
                    println!();
                }
            }
            println!();

            let message = b"Lorem ipsum dolor sit amet";
            println!("\n=== Encryption Test ===");
            println!("Original message: {}", String::from_utf8_lossy(message));

            let start = Instant::now();
            match rsa.encrypt(message) {
                Ok(encrypted) => {
                    let encryption_time = start.elapsed();
                    println!("\nEncryption time: {:?}", encryption_time);
                    println!("Encrypted data ({} bytes):", encrypted.len());
                    for (i, byte) in encrypted.iter().enumerate() {
                        print!("{:02x}", byte);
                        if (i + 1) % 32 == 0 {
                            println!();
                        }
                    }
                    println!();

                    let start = Instant::now();
                    match rsa.decrypt(&encrypted) {
                        Ok(decrypted) => {
                            let decryption_time = start.elapsed();
                            println!("\nDecryption time: {:?}", decryption_time);
                            println!("Decrypted message: {}", String::from_utf8_lossy(&decrypted));
                            let is_valid = message.to_vec() == decrypted;
                            println!(
                                "Decryption validation: {}",
                                if is_valid { "✓ Valid" } else { "✗ Invalid" }
                            );
                        }
                        Err(e) => eprintln!("Error decrypting message: {:?}", e),
                    }
                }
                Err(e) => eprintln!("Error encrypting message: {:?}", e),
            }

            println!("\n=== Signature Test ===");
            let start = Instant::now();
            match rsa.sign(message) {
                Ok(signature) => {
                    let signing_time = start.elapsed();
                    println!("Signing time: {:?}", signing_time);
                    println!("Signature ({} bytes):", signature.len());
                    for (i, byte) in signature.iter().enumerate() {
                        print!("{:02x}", byte);
                        if (i + 1) % 32 == 0 {
                            println!();
                        }
                    }
                    println!();

                    let start = Instant::now();
                    match rsa.verify_signature(message, &signature) {
                        Ok(is_valid) => {
                            let verification_time = start.elapsed();
                            println!("\nVerification time: {:?}", verification_time);
                            println!(
                                "Signature verification: {}",
                                if is_valid { "✓ Valid" } else { "✗ Invalid" }
                            );
                        }
                        Err(e) => eprintln!("Error verifying signature: {:?}", e),
                    }
                }
                Err(e) => eprintln!("Error signing message: {:?}", e),
            }
            println!();
        }
        Err(e) => eprintln!("Error generating RSA keys: {:?}", e),
    }
}
