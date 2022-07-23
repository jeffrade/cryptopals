use crate::util::*;

pub fn start() {
    println!("Starting Set 1, Challenge 5...");
    let stanza_plaintext =
        "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let symmetric_key = "ICE";
    let ciphertext = repeating_key_xor(stanza_plaintext, symmetric_key);
    assert_eq!(
        bytes_to_hex(&ciphertext),
        String::from("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
    );
    println!("Done!")
}
