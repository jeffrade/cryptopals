use crate::util::*;

// https://en.wikipedia.org/wiki/Letter_frequency
pub fn start() {
    println!("Starting Set 1, Challenge 3...");
    let ciphertext: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let ciphertext_bytes = hex_to_bytes(ciphertext);
    let key = find_single_byte_key(&ciphertext_bytes, true);
    let xored: Vec<u8> = bytes_xor(&ciphertext_bytes, &vec![key; ciphertext_bytes.len()]);
    let plaintext = String::from_utf8_lossy(&xored);
    println!("{} deciphered to plaintext {}", key, plaintext);
}
