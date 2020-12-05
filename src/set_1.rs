use std::fs::File;
use std::io::{prelude::*, BufReader};

pub fn challenges() {
    challenge_1(); // https://cryptopals.com/sets/1/challenges/1
    challenge_2(); // https://cryptopals.com/sets/1/challenges/2
    challenge_3(); // https://cryptopals.com/sets/1/challenges/3
    challenge_4(); // https://cryptopals.com/sets/1/challenges/4
}

// https://en.wikipedia.org/wiki/Hexadecimal
// https://en.wikipedia.org/wiki/Base64
pub fn challenge_1() {
    assert_eq!(
        hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"),
        String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
    );
}

// https://www.binaryhexconverter.com/hex-to-binary-converter
// http://www.xor.pw
pub fn challenge_2() {
    assert_eq!(
        hex_xor(
            "1c0111001f010100061a024b53535009181c",
            "686974207468652062756c6c277320657965"
        ),
        String::from("746865206b696420646f6e277420706c6179")
    );
}

// https://en.wikipedia.org/wiki/Letter_frequency
pub fn challenge_3() {
    let cipher_text: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    find_single_byte_key(cipher_text, true);
}

// "Now that the party is jumping"
pub fn challenge_4() {
    let file = File::open("challenge-data/4.txt").unwrap();
    let reader = BufReader::new(file);

    for line in reader.lines() {
        find_single_byte_key(&line.unwrap(), true);
    }
}

fn find_single_byte_key(cipher_text: &str, strictly_ascii: bool) {
    let cipher_bytes: Vec<u8> = hex_to_bytes(cipher_text);
    let cipher_text_check: String = bytes_to_hex(&cipher_bytes);
    assert_eq!(cipher_text, &cipher_text_check); // Sanity check

    for i in 0..=255 {
        let key_guess_bytes: Vec<u8> = vec![i; cipher_bytes.len()];
        let mut key_guess_text: String = String::new();
        for byte in &key_guess_bytes {
            let hex_chars: Vec<char> = byte_to_hex(*byte);
            assert_eq!(hex_chars.len(), 2);
            key_guess_text.push(*hex_chars.first().unwrap());
            key_guess_text.push(*hex_chars.last().unwrap());
        }

        let xored: Vec<u8> = bytes_xor(&cipher_bytes, &key_guess_bytes);
        let xored_check: String = hex_xor(cipher_text, &key_guess_text);
        assert_eq!(&xored, &hex_to_bytes(&xored_check)); // Sanity check

        let plaintext = String::from_utf8_lossy(&xored);
        if strictly_ascii && !plaintext.is_ascii() {
            break;
        }
        let percentages: Vec<f32> = char_analysis_counts(&plaintext);
        let e_per: f32 = percentages[0];
        let t_per: f32 = percentages[1];
        let a_per: f32 = percentages[2];
        let o_per: f32 = percentages[3];
        let i_per: f32 = percentages[4];
        let space_per: f32 = percentages[12];
        // TODO Let's just do something simple for now to only show most likely plaintexts
        if (e_per > 0.13 || t_per > 0.09 || a_per > 0.08 || o_per > 0.07 || i_per > 0.08)
            && space_per > 0.0
        {
            println!(
                "cipher_text {} with key {} produced plaintext {:?}",
                &cipher_text, i, &plaintext
            );
        }
    }
}

fn char_analysis_counts(plaintext: &str) -> Vec<f32> {
    const FREQ_CHARS: [char; 13] = [
        'E', 'T', 'A', 'O', 'I', 'N', 'S', 'H', 'R', 'D', 'L', 'U', ' ',
    ];
    let mut percents: Vec<f32> = Vec::new();
    let str_len = plaintext.chars().count();
    let plaintext_up: String = plaintext.to_uppercase();
    for ch in FREQ_CHARS.iter() {
        let ch_count = match plaintext_up.find(|c: char| &c == ch) {
            Some(count) => count,
            None => 0,
        };
        percents.push(ch_count as f32 / str_len as f32);
    }

    percents
}

fn hex_xor(hex_1: &str, hex_2: &str) -> String {
    let bits_1: Vec<bool> = hex_to_bits(hex_1);
    let bits_2: Vec<bool> = hex_to_bits(hex_2);
    let xored: Vec<bool> = bits_xor(&bits_1, &bits_2);
    bits_to_hex(&xored)
}

fn bits_to_hex(bits: &[bool]) -> String {
    assert_eq!(bits.len() % 4, 0);
    let mut semi_octets: Vec<u8> = Vec::new();
    let chunks = bits.chunks_exact(4);
    let _remainder: &[bool] = chunks.remainder();
    assert_eq!(_remainder.len(), 0);
    for chunk in chunks {
        let mut padded_vec = vec![false, false, false, false];
        padded_vec.extend(chunk);
        semi_octets.push(bits_to_u8(&padded_vec));
    }

    let mut hex: Vec<char> = Vec::new();
    for semi_octet in semi_octets {
        hex.push(semi_octet_to_hex(semi_octet));
    }

    hex.into_iter().collect()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex_str = String::new();
    for byte in bytes {
        let hex_chars: Vec<char> = byte_to_hex(*byte);
        for hex in hex_chars {
            hex_str.push(hex);
        }
    }
    hex_str
}

fn byte_to_hex(byte: u8) -> Vec<char> {
    vec![
        semi_octet_to_hex(byte >> 4),
        semi_octet_to_hex(0b00001111u8 & byte),
    ]
}

fn bytes_xor(bytes_1: &[u8], bytes_2: &[u8]) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();
    assert_eq!(bytes_1.len(), bytes_2.len());
    for (i, byte) in bytes_1.iter().enumerate() {
        result.push(byte ^ bytes_2[i]);
    }
    result
}

// Refactor and DRY up this index padding chaos
fn bits_xor(bits_1: &[bool], bits_2: &[bool]) -> Vec<bool> {
    let mut xored: Vec<bool> = Vec::new();
    let bits_1_len = bits_1.len();
    let bits_2_len = bits_2.len();

    let eq_len = bits_1_len == bits_2_len;

    if eq_len {
        for (i, bit) in bits_1.iter().enumerate() {
            xored.push(bit ^ bits_2[i]);
        }
    } else if bits_1_len < bits_2_len {
        // Maybe use std::cmp::min(bits_1_len, bits_2_len) and check the sign
        let mut bits_1_vec: Vec<bool> = Vec::new();
        let to_pad = bits_2_len - bits_1_len + 1;
        for _i in 1..to_pad {
            bits_1_vec.push(false);
        }
        bits_1_vec.extend(bits_1);
        for (i, bit) in bits_2.iter().enumerate() {
            xored.push(bit ^ bits_1_vec[i]);
        }
    } else {
        let mut bits_2_vec: Vec<bool> = Vec::new();
        let to_pad = bits_1_len - bits_2_len + 1;
        for _i in 1..to_pad {
            bits_2_vec.push(false);
        }
        bits_2_vec.extend(bits_2);
        for (i, bit) in bits_1.iter().enumerate() {
            xored.push(bit ^ bits_2_vec[i]);
        }
    }
    xored
}

fn hex_to_base64(hex_str: &str) -> String {
    let bits: Vec<bool> = hex_to_bits(hex_str);

    let mut base64_result = String::new();
    let chunks = bits.chunks_exact(6);
    let remainder: &[bool] = chunks.remainder();
    for chunk in chunks {
        let b64_char: char = six_bits_to_b64(&chunk);
        base64_result.push(b64_char);
    }

    if !remainder.is_empty() {
        let final_chunk: [bool; 6] = fill_6_bit_block(&remainder);
        let final_b64_char: char = six_bits_to_b64(&final_chunk);
        base64_result.push(final_b64_char);
    }

    let bits_length: usize = bits.len();
    let empty_bit_length: usize = bits_length % 24;
    if bits_length == 8 {
        base64_result.push('=');
        base64_result.push('=');
    } else if bits_length == 16 {
        base64_result.push('=');
    } else if empty_bit_length > 0 {
        if empty_bit_length == 8 {
            base64_result.push('=');
            base64_result.push('=');
        } else if empty_bit_length == 16 {
            base64_result.push('=');
        } else {
            panic!("Wrong length of bits during conversion: {:?}", bits_length);
        }
    }

    base64_result
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    let hex_chars: Vec<char> = hex.chars().collect();
    let hex_bytes = hex_chars.chunks_exact(2);
    let remainder: &[char] = hex_bytes.remainder();

    assert_eq!(hex.len() % 2, 0); //TODO handle odd number of chars with '0' padding prefix
    assert_eq!(remainder.is_empty(), true); //TODO handle odd number of chars with '0' padding prefix

    for hex_byte in hex_bytes {
        bytes.push(hex_to_byte(&hex_byte));
    }

    bytes
}

fn hex_to_byte(hex_chars: &[char]) -> u8 {
    assert_eq!(hex_chars.len(), 2);
    let first: char = hex_chars[0];
    let last: char = hex_chars[1];
    (hex_to_semi_octet(first) << 4) + hex_to_semi_octet(last)
}

fn hex_to_bits(hex: &str) -> Vec<bool> {
    let hex_chars: Vec<char> = hex.chars().collect();
    hex_vec_to_bit_vec(&hex_chars)
}

fn fill_6_bit_block(bits: &[bool]) -> [bool; 6] {
    let mut final_block: [bool; 6] = [false, false, false, false, false, false];
    for (i, bit) in bits.iter().enumerate() {
        final_block[i] = *bit;
    }
    final_block
}

fn hex_vec_to_bit_vec(hex_chars: &[char]) -> Vec<bool> {
    let mut bits: Vec<bool> = Vec::new();
    for hex_char in hex_chars.iter() {
        let binary: u8 = hex_to_semi_octet(*hex_char);
        let semi_octet_bits: Vec<bool> = u8_to_bits(binary).split_off(4);
        for bit in semi_octet_bits.iter() {
            bits.push(*bit);
        }
    }
    bits
}

fn hex_to_semi_octet(hex_char: char) -> u8 {
    if hex_char == '0' {
        0b00000000u8
    } else if hex_char == '1' {
        0b00000001u8
    } else if hex_char == '2' {
        0b00000010u8
    } else if hex_char == '3' {
        0b00000011u8
    } else if hex_char == '4' {
        0b00000100u8
    } else if hex_char == '5' {
        0b00000101u8
    } else if hex_char == '6' {
        0b00000110u8
    } else if hex_char == '7' {
        0b00000111u8
    } else if hex_char == '8' {
        0b00001000u8
    } else if hex_char == '9' {
        0b00001001u8
    } else if hex_char == 'a' {
        0b00001010u8
    } else if hex_char == 'b' {
        0b00001011u8
    } else if hex_char == 'c' {
        0b00001100u8
    } else if hex_char == 'd' {
        0b00001101u8
    } else if hex_char == 'e' {
        0b00001110u8
    } else if hex_char == 'f' {
        0b00001111u8
    } else {
        panic!("Received a char that I cannot handle: {:?}", hex_char)
    }
}

fn semi_octet_to_hex(binary: u8) -> char {
    if binary == 0b00000000u8 {
        '0'
    } else if binary == 0b00000001u8 {
        '1'
    } else if binary == 0b00000010u8 {
        '2'
    } else if binary == 0b00000011u8 {
        '3'
    } else if binary == 0b00000100u8 {
        '4'
    } else if binary == 0b00000101u8 {
        '5'
    } else if binary == 0b00000110u8 {
        '6'
    } else if binary == 0b00000111u8 {
        '7'
    } else if binary == 0b00001000u8 {
        '8'
    } else if binary == 0b00001001u8 {
        '9'
    } else if binary == 0b00001010u8 {
        'a'
    } else if binary == 0b00001011u8 {
        'b'
    } else if binary == 0b00001100u8 {
        'c'
    } else if binary == 0b00001101u8 {
        'd'
    } else if binary == 0b00001110u8 {
        'e'
    } else if binary == 0b00001111u8 {
        'f'
    } else {
        panic!("Received a u8 that I cannot handle: {:?}", binary)
    }
}

fn u8_to_bits(binary: u8) -> Vec<bool> {
    let mut result: Vec<bool> = Vec::new();
    for i in 0..8 {
        let bit: bool = ((binary >> i) % 2) == 0b00000001u8;
        result.push(bit);
    }
    result.reverse();
    result
}

fn bits_to_u8(bits: &[bool]) -> u8 {
    let mut result: u8 = 0;
    for (i, b) in bits.iter().rev().enumerate() {
        let to_add = if *b { 1 << i } else { 0 << i };
        result += to_add;
    }

    result
}

fn six_bits_to_b64(bit_vec: &[bool]) -> char {
    if bit_vec == [false, false, false, false, false, false] {
        'A'
    } else if bit_vec == [false, false, false, false, false, true] {
        'B'
    } else if bit_vec == [false, false, false, false, true, false] {
        'C'
    } else if bit_vec == [false, false, false, false, true, true] {
        'D'
    } else if bit_vec == [false, false, false, true, false, false] {
        'E'
    } else if bit_vec == [false, false, false, true, false, true] {
        'F'
    } else if bit_vec == [false, false, false, true, true, false] {
        'G'
    } else if bit_vec == [false, false, false, true, true, true] {
        'H'
    } else if bit_vec == [false, false, true, false, false, false] {
        'I'
    } else if bit_vec == [false, false, true, false, false, true] {
        'J'
    } else if bit_vec == [false, false, true, false, true, false] {
        'K'
    } else if bit_vec == [false, false, true, false, true, true] {
        'L'
    } else if bit_vec == [false, false, true, true, false, false] {
        'M'
    } else if bit_vec == [false, false, true, true, false, true] {
        'N'
    } else if bit_vec == [false, false, true, true, true, false] {
        'O'
    } else if bit_vec == [false, false, true, true, true, true] {
        'P'
    } else if bit_vec == [false, true, false, false, false, false] {
        'Q'
    } else if bit_vec == [false, true, false, false, false, true] {
        'R'
    } else if bit_vec == [false, true, false, false, true, false] {
        'S'
    } else if bit_vec == [false, true, false, false, true, true] {
        'T'
    } else if bit_vec == [false, true, false, true, false, false] {
        'U'
    } else if bit_vec == [false, true, false, true, false, true] {
        'V'
    } else if bit_vec == [false, true, false, true, true, false] {
        'W'
    } else if bit_vec == [false, true, false, true, true, true] {
        'X'
    } else if bit_vec == [false, true, true, false, false, false] {
        'Y'
    } else if bit_vec == [false, true, true, false, false, true] {
        'Z'
    } else if bit_vec == [false, true, true, false, true, false] {
        'a'
    } else if bit_vec == [false, true, true, false, true, true] {
        'b'
    } else if bit_vec == [false, true, true, true, false, false] {
        'c'
    } else if bit_vec == [false, true, true, true, false, true] {
        'd'
    } else if bit_vec == [false, true, true, true, true, false] {
        'e'
    } else if bit_vec == [false, true, true, true, true, true] {
        'f'
    } else if bit_vec == [true, false, false, false, false, false] {
        'g'
    } else if bit_vec == [true, false, false, false, false, true] {
        'h'
    } else if bit_vec == [true, false, false, false, true, false] {
        'i'
    } else if bit_vec == [true, false, false, false, true, true] {
        'j'
    } else if bit_vec == [true, false, false, true, false, false] {
        'k'
    } else if bit_vec == [true, false, false, true, false, true] {
        'l'
    } else if bit_vec == [true, false, false, true, true, false] {
        'm'
    } else if bit_vec == [true, false, false, true, true, true] {
        'n'
    } else if bit_vec == [true, false, true, false, false, false] {
        'o'
    } else if bit_vec == [true, false, true, false, false, true] {
        'p'
    } else if bit_vec == [true, false, true, false, true, false] {
        'q'
    } else if bit_vec == [true, false, true, false, true, true] {
        'r'
    } else if bit_vec == [true, false, true, true, false, false] {
        's'
    } else if bit_vec == [true, false, true, true, false, true] {
        't'
    } else if bit_vec == [true, false, true, true, true, false] {
        'u'
    } else if bit_vec == [true, false, true, true, true, true] {
        'v'
    } else if bit_vec == [true, true, false, false, false, false] {
        'w'
    } else if bit_vec == [true, true, false, false, false, true] {
        'x'
    } else if bit_vec == [true, true, false, false, true, false] {
        'y'
    } else if bit_vec == [true, true, false, false, true, true] {
        'z'
    } else if bit_vec == [true, true, false, true, false, false] {
        '0'
    } else if bit_vec == [true, true, false, true, false, true] {
        '1'
    } else if bit_vec == [true, true, false, true, true, false] {
        '2'
    } else if bit_vec == [true, true, false, true, true, true] {
        '3'
    } else if bit_vec == [true, true, true, false, false, false] {
        '4'
    } else if bit_vec == [true, true, true, false, false, true] {
        '5'
    } else if bit_vec == [true, true, true, false, true, false] {
        '6'
    } else if bit_vec == [true, true, true, false, true, true] {
        '7'
    } else if bit_vec == [true, true, true, true, false, false] {
        '8'
    } else if bit_vec == [true, true, true, true, false, true] {
        '9'
    } else if bit_vec == [true, true, true, true, true, false] {
        '+'
    } else if bit_vec == [true, true, true, true, true, true] {
        '/'
    } else {
        panic!("Received a vec that I cannot handle: {:?}", bit_vec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_to_byte() {
        assert_eq!(hex_to_byte(&['0', '0']), 0b00000000u8);
        assert_eq!(hex_to_byte(&['f', 'f']), 0b11111111u8);
        assert_eq!(hex_to_byte(&['1', '0']), 0b00010000u8);
    }

    #[test]
    fn test_hex_to_bytes() {
        assert_eq!(hex_to_bytes("0000"), vec![0b00000000u8, 0b00000000u8]);
        assert_eq!(hex_to_bytes("ff00"), vec![0b11111111u8, 0b00000000u8]);
        assert_eq!(hex_to_bytes("10ff00"), vec![0b00010000u8, 0b11111111u8, 0b00000000u8]);
    }

    #[test]
    fn test_bits_to_hex() {
        assert_eq!(bits_to_hex(&[false, false, false, false]), "0");
        assert_eq!(bits_to_hex(&[false, false, false, false, false, false, false, false]), "00");
        assert_eq!(bits_to_hex(&[true, true, true, true, false, false, false, false, false, false, false, false]), "f00");
        assert_eq!(bits_to_hex(&[true, false, true, true, true, false, true, false, false, true, true, true]), "ba7");
    }

    #[test]
    fn test_bytes_xor() {
        assert_eq!(bytes_xor(&[1], &[0]), vec![1]);
        assert_eq!(bytes_xor(&[1], &[1]), vec![0]);
        assert_eq!(bytes_xor(&[21, 175], &[110, 43]), vec![123, 132]);
    }

    #[test]
    fn test_byte_to_hex() {
        assert_eq!(byte_to_hex(0), ['0', '0']);
        assert_eq!(byte_to_hex(9), ['0', '9']);
        assert_eq!(byte_to_hex(10), ['0', 'a']);
        assert_eq!(byte_to_hex(15), ['0', 'f']);
        assert_eq!(byte_to_hex(16), ['1', '0']);
        assert_eq!(byte_to_hex(255), ['f', 'f']);
    }

    #[test]
    fn test_bytes_to_hex() {
        assert_eq!(bytes_to_hex(&[10]), "0a");
        assert_eq!(bytes_to_hex(&[0]), "00");
        assert_eq!(bytes_to_hex(&[255, 15, 0, 100, 9, 1]), "ff0f00640901");
        assert_eq!(
            bytes_to_hex(&[0b10101010u8, 0b11111111u8, 0b00000000u8, 0b11111111u8]),
            "aaff00ff"
        );
    }

    #[test]
    fn test_hex_to_base64_without_padding() {
        // https://base64.guru/converter/encode/hex
        assert_eq!(hex_to_base64("4d616e"), String::from("TWFu"));
        assert_eq!(hex_to_base64("7a0c00"), String::from("egwA"));
        assert_eq!(
            hex_to_base64("ba192d5e650d2cf3ddd2f6b28f912870557e2a74555cf564"),
            String::from("uhktXmUNLPPd0vayj5EocFV+KnRVXPVk")
        );
    }

    #[test]
    fn test_hex_to_base64_with_padding() {
        // https://base64.guru/converter/encode/hex
        assert_eq!(hex_to_base64("4d61"), String::from("TWE="));
        assert_eq!(hex_to_base64("4d"), String::from("TQ=="));
        assert_eq!(hex_to_base64("ba"), String::from("ug=="));
        assert_eq!(hex_to_base64("401d2cd0"), String::from("QB0s0A=="));
        assert_eq!(
            hex_to_base64("342679abc567d98ef54321ade979"),
            String::from("NCZ5q8Vn2Y71QyGt6Xk=")
        );
    }

    #[test]
    fn test_bits_xor() {
        assert_eq!(vec![false], bits_xor(&[false], &[false]));
        assert_eq!(vec![false], bits_xor(&[true], &[true]));
        assert_eq!(vec![true], bits_xor(&[false], &[true]));

        assert_eq!(
            vec![false, false, false],
            bits_xor(&[false, true, true], &[false, true, true])
        );
        assert_eq!(
            vec![true, true, true],
            bits_xor(&[false, true, true], &[true, false, false])
        );

        assert_eq!(
            vec![true, true, true, false],
            bits_xor(&[true, true, false], &[true, false, false, false])
        );
    }

    #[test]
    fn test_bits_to_u8() {
        assert_eq!(0, bits_to_u8(&[false]));
        assert_eq!(0, bits_to_u8(&[false, false]));
        assert_eq!(1, bits_to_u8(&[true]));
        assert_eq!(2, bits_to_u8(&[true, false]));
        assert_eq!(1, bits_to_u8(&[false, true]));
        assert_eq!(2, bits_to_u8(&[false, true, false]));
        assert_eq!(6, bits_to_u8(&[true, true, false]));
        assert_eq!(7, bits_to_u8(&[true, true, true]));
        assert_eq!(
            118,
            bits_to_u8(&[false, true, true, true, false, true, true, false])
        );
        assert_eq!(
            255,
            bits_to_u8(&[true, true, true, true, true, true, true, true])
        );
    }

    #[test]
    fn test_u8_to_bits() {
        assert_eq!(
            u8_to_bits(0b00000000u8),
            [false, false, false, false, false, false, false, false]
        );
        assert_eq!(
            u8_to_bits(0b00000001u8),
            [false, false, false, false, false, false, false, true]
        );
        assert_eq!(
            u8_to_bits(0b00000010u8),
            [false, false, false, false, false, false, true, false]
        );
        assert_eq!(
            u8_to_bits(0b00010000u8),
            [false, false, false, true, false, false, false, false]
        );
        assert_eq!(
            u8_to_bits(0b00010001u8),
            [false, false, false, true, false, false, false, true]
        );
        assert_eq!(
            u8_to_bits(0b11111111u8),
            [true, true, true, true, true, true, true, true]
        );
    }
}
