use crate::util::*;

// https://www.binaryhexconverter.com/hex-to-binary-converter
// http://www.xor.pw
pub fn start() {
    println!("Starting Set 1, Challenge 2...");
    assert_eq!(
        hex_xor(
            "1c0111001f010100061a024b53535009181c",
            "686974207468652062756c6c277320657965"
        ),
        String::from("746865206b696420646f6e277420706c6179")
    );
    println!("Done!")
}
