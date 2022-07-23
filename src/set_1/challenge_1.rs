use crate::util::hex_to_base64;

// https://en.wikipedia.org/wiki/Hexadecimal
// https://en.wikipedia.org/wiki/Base64
pub fn start() {
    println!("Starting Set 1, Challenge 1...");
    assert_eq!(
        hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"),
        String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
    );
    println!("Done!")
}
