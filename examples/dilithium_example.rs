use cryptolib::SecureDilithium;
use std::time::Instant;

fn main() {
    println!("\n=== Dilithium Example ===");
    println!();

    let start = Instant::now();
    let mut dilithium = SecureDilithium::new();
    match dilithium.generate_keypair() {
        Ok((private_key, public_key)) => {
            let key_gen_time = start.elapsed();
            println!("=== Dilithium5 Key Generation ===");
            println!("Generation time: {:?}", key_gen_time);

            println!("\nPrivate Key ({} bytes):", private_key.len());
            for (i, byte) in private_key.iter().enumerate() {
                print!("{:02x}", byte);
                if (i + 1) % 32 == 0 {
                    println!();
                }
            }
            println!();

            println!("\nPublic Key ({} bytes):", public_key.len());
            for (i, byte) in public_key.iter().enumerate() {
                print!("{:02x}", byte);
                if (i + 1) % 32 == 0 {
                    println!();
                }
            }
            println!();

            let message = b"Lorem ipsum dolor sit amet";
            println!("\n=== Signature Test ===");
            println!("Original message: {}", String::from_utf8_lossy(message));

            let start = Instant::now();
            match dilithium.sign(message) {
                Ok(signature) => {
                    let signing_time = start.elapsed();
                    println!("\nSigning time: {:?}", signing_time);
                    println!("Signature ({} bytes):", signature.len());
                    for (i, byte) in signature.iter().enumerate() {
                        print!("{:02x}", byte);
                        if (i + 1) % 32 == 0 {
                            println!();
                        }
                    }
                    println!();

                    let start = Instant::now();
                    match dilithium.verify_signature(message, &signature) {
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
        Err(e) => eprintln!("Error generating Dilithium keys: {:?}", e),
    }
}
