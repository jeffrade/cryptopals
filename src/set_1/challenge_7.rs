use crate::crypto::*;
use crate::util::*;

// openssl enc -d -a -aes-128-ecb -K 59454c4c4f57205355424d4152494e45 -in challenge-data/7.txt
pub fn start() {
    println!("Starting Set 1, Challenge 7...");
    let key: &[u8] = "YELLOW SUBMARINE".as_bytes();
    let mut ciphertext = Vec::<u8>::new();
    for line in get_file_lines("challenge-data/7.txt") {
        ciphertext.append(&mut hex_to_bytes(&base64_to_hex(&line.unwrap())));
    }

    let chunks: usize = ciphertext.len() / 16;
    for index in 0..chunks {
        let start: usize = index * 16;
        let end: usize = start + 16;
        let plaintext_bytes = aes128_ecb_decrypt(&ciphertext[start..end], key);
        println!("{:?}", String::from_utf8_lossy(&plaintext_bytes));
    }

    println!("Done!")
}
