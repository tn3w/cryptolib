use cryptolib::SecurePbkdf2;
use std::time::Instant;

fn main() {
    println!("\n=== PBKDF2 Example ===");
    println!();

    let data = b"Lorem ipsum dolor sit amet";
    println!("Original password: {}", String::from_utf8_lossy(data));
    let hasher = SecurePbkdf2::new();

    let start = Instant::now();
    match hasher.hash_password(data) {
        Ok(hash) => {
            let hash_time = start.elapsed();
            println!("\nHash time: {:?}", hash_time);
            println!("Hash ({} bytes):", hash.len());
            for (i, byte) in hash.iter().enumerate() {
                print!("{:02x}", byte);
                if (i + 1) % 32 == 0 {
                    println!();
                }
            }
            println!();

            let start = Instant::now();
            match hasher.verify_password(data, &hash) {
                Ok(verified) => {
                    let verify_time = start.elapsed();
                    println!("\nVerify time: {:?}", verify_time);
                    println!(
                        "Hash verification: {}",
                        if verified { "✓ Valid" } else { "✗ Invalid" }
                    );
                }
                Err(e) => eprintln!("Verification error: {:?}", e),
            }
        }
        Err(e) => eprintln!("Hashing error: {:?}", e),
    }
}
