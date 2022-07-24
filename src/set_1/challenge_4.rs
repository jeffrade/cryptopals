use crate::util::*;

pub fn start() {
    println!("Starting Set 1, Challenge 4...");
    for line in get_file_lines("challenge-data/4.txt") {
        let ciphertext_bytes = hex_to_bytes(&line.unwrap());
        let key = find_single_byte_key(&ciphertext_bytes, true);
        let xored: Vec<u8> = bytes_xor(&ciphertext_bytes, &vec![key; ciphertext_bytes.len()]);
        let plaintext = String::from_utf8_lossy(&xored);
        if resembles_english(&plaintext) {
            println!("{} deciphered to plaintext {}", key, plaintext);
        }
    }
}
