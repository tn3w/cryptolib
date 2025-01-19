use cryptolib::SecureKyber;
use std::time::Instant;

fn main() {
    println!("\n=== Kyber Example ===");
    println!();

    let start = Instant::now();

    let mut kyber = SecureKyber::new();
    match kyber.generate_keypair() {
        Ok((private_key, public_key)) => {
            println!("=== Kyber Key Generation ===");
            let generation_time = start.elapsed();
            println!("Generation time: {:?}", generation_time);

            println!("\nPublic Key ({} bytes):", public_key.len());
            for (i, byte) in public_key.iter().enumerate() {
                print!("{:02x}", byte);
                if (i + 1) % 32 == 0 {
                    println!();
                }
            }
            println!();

            println!("\nPrivate Key ({} bytes):", private_key.len());
            for (i, byte) in private_key.iter().enumerate() {
                print!("{:02x}", byte);
                if (i + 1) % 32 == 0 {
                    println!();
                }
            }
            println!();

            println!("\n=== Encryption Test ===");
            let message = b"Lorem ipsum dolor sit amet";
            println!("Original message: {}", String::from_utf8_lossy(message));

            let start = Instant::now();
            match kyber.encrypt(message) {
                Ok(encrypted) => {
                    let encryption_time = start.elapsed();
                    println!("\nEncryption time: {:?}", encryption_time);
                    println!("\nEncrypted data ({} bytes):", encrypted.len());
                    for (i, byte) in encrypted.iter().enumerate() {
                        print!("{:02x}", byte);
                        if (i + 1) % 32 == 0 {
                            println!();
                        }
                    }
                    println!();

                    let start = Instant::now();
                    match kyber.decrypt(&encrypted) {
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
                Err(e) => eprintln!("Encryption error: {}", e),
            }
        }
        Err(e) => eprintln!("Key generation error: {}", e),
    }
}
