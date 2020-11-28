pub fn challenges() {
    challenge_1(); // https://cryptopals.com/sets/1/challenges/1
    challenge_2(); // https://cryptopals.com/sets/1/challenges/2
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
// www.xor.pw
pub fn challenge_2() {
    assert_eq!(
        hex_xor(
            "1c0111001f010100061a024b53535009181c",
            "686974207468652062756c6c277320657965"
        ),
        String::from("746865206b696420646f6e277420706c6179")
    );
}

fn hex_xor(hex_1: &str, hex_2: &str) -> String {
    let bits_1: Vec<bool> = hex_to_bits(hex_1);
    let bits_2: Vec<bool> = hex_to_bits(hex_2);
    let xored: Vec<bool> = bits_xor(&bits_1, &bits_2);

    let mut bytes: Vec<u8> = Vec::new();
    let chunks = xored.chunks_exact(4);
    let _remainder: &[bool] = chunks.remainder();
    assert_eq!(_remainder.len(), 0);
    for chunk in chunks {
        let mut padded_vec = vec![false, false, false, false];
        padded_vec.extend(chunk);
        bytes.push(bits_to_u8(&padded_vec));
    }

    let mut hex: Vec<char> = Vec::new();
    for byte in bytes {
        hex.push(binary_to_hex(byte));
    }

    hex.into_iter().collect()
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
        bits_2_vec.extend(bits_1);
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
            panic!("Wrong length of bits during conversion!");
        }
    }

    base64_result
}

fn hex_to_bits(hex: &str) -> Vec<bool> {
    let hex_chars: Vec<char> = hex.chars().collect(); //8 bits = range from 00000000-00001111 = range from 0-F = range from 0-15
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
    let mut bits: Vec<bool> = Vec::new(); //bits
    for hex_char in hex_chars.iter() {
        let binary: u8 = hex_to_binary(*hex_char);
        let semi_octet_bits: Vec<bool> = u8_to_bits(binary).split_off(4);
        for bit in semi_octet_bits.iter() {
            bits.push(*bit);
        }
    }
    bits
}

fn hex_to_binary(hex_char: char) -> u8 {
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
        panic!("Received a char that I cannot handle!")
    }
}

fn binary_to_hex(binary: u8) -> char {
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
        panic!("Received a u8 that I cannot handle!")
    }
}

fn u8_to_bits(binary: u8) -> Vec<bool> {
    if binary == 0b0000u8 {
        vec![false, false, false, false, false, false, false, false]
    } else if binary == 0b0001u8 {
        vec![false, false, false, false, false, false, false, true]
    } else if binary == 0b0010u8 {
        vec![false, false, false, false, false, false, true, false]
    } else if binary == 0b0011u8 {
        vec![false, false, false, false, false, false, true, true]
    } else if binary == 0b0100u8 {
        vec![false, false, false, false, false, true, false, false]
    } else if binary == 0b0101u8 {
        vec![false, false, false, false, false, true, false, true]
    } else if binary == 0b0110u8 {
        vec![false, false, false, false, false, true, true, false]
    } else if binary == 0b0111u8 {
        vec![false, false, false, false, false, true, true, true]
    } else if binary == 0b1000u8 {
        vec![false, false, false, false, true, false, false, false]
    } else if binary == 0b1001u8 {
        vec![false, false, false, false, true, false, false, true]
    } else if binary == 0b1010u8 {
        vec![false, false, false, false, true, false, true, false]
    } else if binary == 0b1011u8 {
        vec![false, false, false, false, true, false, true, true]
    } else if binary == 0b1100u8 {
        vec![false, false, false, false, true, true, false, false]
    } else if binary == 0b1101u8 {
        vec![false, false, false, false, true, true, false, true]
    } else if binary == 0b1110u8 {
        vec![false, false, false, false, true, true, true, false]
    } else if binary == 0b1111u8 {
        vec![false, false, false, false, true, true, true, true]
    } else if binary == 0b00010000u8 {
        vec![false, false, false, true, false, false, false, false]
    } else {
        panic!("Received a u8 that I cannot handle!")
    }
}

fn bits_to_u8(bits: &[bool]) -> u8 {
    if bits == [false, false, false, false, false, false, false, false] {
        0b00000000u8
    } else if bits == [false, false, false, false, false, false, false, true] {
        0b00000001u8
    } else if bits == [false, false, false, false, false, false, true, false] {
        0b00000010u8
    } else if bits == [false, false, false, false, false, false, true, true] {
        0b00000011u8
    } else if bits == [false, false, false, false, false, true, false, false] {
        0b00000100u8
    } else if bits == [false, false, false, false, false, true, false, true] {
        0b00000101u8
    } else if bits == [false, false, false, false, false, true, true, false] {
        0b00000110u8
    } else if bits == [false, false, false, false, false, true, true, true] {
        0b00000111u8
    } else if bits == [false, false, false, false, true, false, false, false] {
        0b00001000u8
    } else if bits == [false, false, false, false, true, false, false, true] {
        0b00001001u8
    } else if bits == [false, false, false, false, true, false, true, false] {
        0b00001010u8
    } else if bits == [false, false, false, false, true, false, true, true] {
        0b00001011u8
    } else if bits == [false, false, false, false, true, true, false, false] {
        0b00001100u8
    } else if bits == [false, false, false, false, true, true, false, true] {
        0b00001101u8
    } else if bits == [false, false, false, false, true, true, true, false] {
        0b00001110u8
    } else if bits == [false, false, false, false, true, true, true, true] {
        0b00001111u8
    } else {
        panic!("Received a Vec<bool> that I cannot handle!")
    }
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
        panic!("Received a vec that I cannot handle!")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}