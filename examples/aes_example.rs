use cryptolib::SecureAES;
use std::time::Instant;

fn main() {
    println!("\n=== AES Example ===");
    println!();

    let secret = b"lorem_ipsum_dolor_sit_amet";
    let data = b"Lorem ipsum dolor sit amet".to_vec();
    println!("Original message: {}", String::from_utf8_lossy(&data));

    match SecureAES::new(secret) {
        Ok(encryptor) => {
            let start = Instant::now();
            match encryptor.encrypt(&data) {
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
                    match encryptor.decrypt(&encrypted) {
                        Ok(decrypted) => {
                            let decryption_time = start.elapsed();
                            println!("\nDecryption time: {:?}", decryption_time);
                            println!("Decrypted message: {}", String::from_utf8_lossy(&decrypted));
                            let is_valid = data == decrypted;
                            println!(
                                "Decryption validation: {}",
                                if is_valid { "✓ Valid" } else { "✗ Invalid" }
                            );
                        }
                        Err(e) => eprintln!("Decryption error: {}", e),
                    }
                }
                Err(e) => eprintln!("Encryption error: {}", e),
            }
        }
        Err(e) => eprintln!("Initialization error: {}", e),
    }
}
