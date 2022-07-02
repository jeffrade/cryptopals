use std::cmp::Ordering;

pub fn hex_xor(hex_1: &str, hex_2: &str) -> String {
    let bits_1: Vec<u8> = hex_to_bits(hex_1);
    let bits_2: Vec<u8> = hex_to_bits(hex_2);
    let xored: Vec<u8> = bits_xor(&bits_1, &bits_2);
    bits_to_hex(&xored)
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex_str = String::new();
    for byte in bytes {
        let hex_chars: Vec<char> = byte_to_hex(*byte);
        for hex in hex_chars {
            hex_str.push(hex);
        }
    }
    hex_str
}

pub fn byte_to_hex(byte: u8) -> Vec<char> {
    vec![
        semi_octet_to_hex(byte >> 4),
        semi_octet_to_hex(0b00001111u8 & byte),
    ]
}

pub fn bytes_xor(bytes_1: &[u8], bytes_2: &[u8]) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();
    assert_eq!(bytes_1.len(), bytes_2.len());
    for (i, byte) in bytes_1.iter().enumerate() {
        result.push(byte ^ bytes_2[i]);
    }
    result
}

pub fn hex_to_base64(hex_str: &str) -> String {
    let bits: Vec<u8> = hex_to_bits(hex_str);

    let mut base64_result = String::new();
    let chunks = bits.chunks_exact(6);
    let remainder: &[u8] = chunks.remainder();
    for chunk in chunks {
        let b64_char: char = six_bits_to_b64(chunk);
        base64_result.push(b64_char);
    }

    if !remainder.is_empty() {
        let final_chunk: [u8; 6] = fill_6_bit_block(remainder);
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

pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    let hex_chars: Vec<char> = hex.chars().collect();
    let hex_bytes = hex_chars.chunks_exact(2);
    let remainder: &[char] = hex_bytes.remainder();

    assert_eq!(hex.len() % 2, 0); //TODO handle odd number of chars with '0' padding prefix
    assert!(remainder.is_empty()); //TODO handle odd number of chars with '0' padding prefix

    for hex_byte in hex_bytes {
        bytes.push(hex_to_byte(hex_byte));
    }

    bytes
}

fn bits_to_hex(bits: &[u8]) -> String {
    assert_eq!(bits.len() % 4, 0);
    let mut semi_octets: Vec<u8> = Vec::new();
    let chunks = bits.chunks_exact(4);
    let _remainder: &[u8] = chunks.remainder();
    assert_eq!(_remainder.len(), 0);
    for chunk in chunks {
        let mut padded_vec = vec![0b0u8, 0b0u8, 0b0u8, 0b0u8];
        padded_vec.extend(chunk);
        semi_octets.push(bits_to_u8(&padded_vec));
    }

    let mut hex: Vec<char> = Vec::new();
    for semi_octet in semi_octets {
        hex.push(semi_octet_to_hex(semi_octet));
    }

    hex.into_iter().collect()
}

// Refactor and DRY up this index padding chaos
fn bits_xor(bits_1: &[u8], bits_2: &[u8]) -> Vec<u8> {
    let mut xored: Vec<u8> = Vec::new();
    let bits_1_len = bits_1.len();
    let bits_2_len = bits_2.len();

    match bits_1_len.cmp(&bits_2_len) {
        Ordering::Greater => {
            let mut bits_2_vec: Vec<u8> = Vec::new();
            let to_pad = bits_1_len - bits_2_len + 1;
            for _i in 1..to_pad {
                bits_2_vec.push(0b0u8);
            }
            bits_2_vec.extend(bits_2);
            for (i, bit) in bits_1.iter().enumerate() {
                xored.push(bit ^ bits_2_vec[i]);
            }
        }
        Ordering::Less => {
            // Maybe use std::cmp::min(bits_1_len, bits_2_len) and check the sign
            let mut bits_1_vec: Vec<u8> = Vec::new();
            let to_pad = bits_2_len - bits_1_len + 1;
            for _i in 1..to_pad {
                bits_1_vec.push(0b0u8);
            }
            bits_1_vec.extend(bits_1);
            for (i, bit) in bits_2.iter().enumerate() {
                xored.push(bit ^ bits_1_vec[i]);
            }
        }
        Ordering::Equal => {
            for (i, bit) in bits_1.iter().enumerate() {
                xored.push(bit ^ bits_2[i]);
            }
        }
    }

    xored
}

fn hex_to_byte(hex_chars: &[char]) -> u8 {
    assert_eq!(hex_chars.len(), 2);
    let first: char = hex_chars[0];
    let last: char = hex_chars[1];
    (hex_to_semi_octet(first) << 4) + hex_to_semi_octet(last)
}

fn hex_to_bits(hex: &str) -> Vec<u8> {
    let hex_chars: Vec<char> = hex.chars().collect();
    hex_vec_to_bit_vec(&hex_chars)
}

fn fill_6_bit_block(bits: &[u8]) -> [u8; 6] {
    let mut final_block: [u8; 6] = [0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8];
    for (i, bit) in bits.iter().enumerate() {
        final_block[i] = *bit;
    }
    final_block
}

fn hex_vec_to_bit_vec(hex_chars: &[char]) -> Vec<u8> {
    let mut bits: Vec<u8> = Vec::new();
    for hex_char in hex_chars.iter() {
        let binary: u8 = hex_to_semi_octet(*hex_char);
        let semi_octet_bits: Vec<u8> = u8_to_bits(binary).split_off(4);
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

//TODO This isn't efficient
fn u8_to_bits(binary: u8) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();
    for i in 0..8 {
        match ((binary >> i) % 2) == 0b1u8 {
            true => result.push(0b1u8),
            false => result.push(0b0u8),
        }
    }
    result.reverse();
    result
}

fn bits_to_u8(bits: &[u8]) -> u8 {
    let mut result: u8 = 0;
    for (i, bit) in bits.iter().rev().enumerate() {
        match bit {
            0b1u8 => result += 1 << i,
            0b0u8 => result += 0 << i,
            _ => panic!("Not operating in bits!"),
        }
    }

    result
}

fn six_bits_to_b64(bit_vec: &[u8]) -> char {
    if bit_vec == [0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8] {
        'A'
    } else if bit_vec == [0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b1u8] {
        'B'
    } else if bit_vec == [0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b1u8, 0b0u8] {
        'C'
    } else if bit_vec == [0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b1u8, 0b1u8] {
        'D'
    } else if bit_vec == [0b0u8, 0b0u8, 0b0u8, 0b1u8, 0b0u8, 0b0u8] {
        'E'
    } else if bit_vec == [0b0u8, 0b0u8, 0b0u8, 0b1u8, 0b0u8, 0b1u8] {
        'F'
    } else if bit_vec == [0b0u8, 0b0u8, 0b0u8, 0b1u8, 0b1u8, 0b0u8] {
        'G'
    } else if bit_vec == [0b0u8, 0b0u8, 0b0u8, 0b1u8, 0b1u8, 0b1u8] {
        'H'
    } else if bit_vec == [0b0u8, 0b0u8, 0b1u8, 0b0u8, 0b0u8, 0b0u8] {
        'I'
    } else if bit_vec == [0b0u8, 0b0u8, 0b1u8, 0b0u8, 0b0u8, 0b1u8] {
        'J'
    } else if bit_vec == [0b0u8, 0b0u8, 0b1u8, 0b0u8, 0b1u8, 0b0u8] {
        'K'
    } else if bit_vec == [0b0u8, 0b0u8, 0b1u8, 0b0u8, 0b1u8, 0b1u8] {
        'L'
    } else if bit_vec == [0b0u8, 0b0u8, 0b1u8, 0b1u8, 0b0u8, 0b0u8] {
        'M'
    } else if bit_vec == [0b0u8, 0b0u8, 0b1u8, 0b1u8, 0b0u8, 0b1u8] {
        'N'
    } else if bit_vec == [0b0u8, 0b0u8, 0b1u8, 0b1u8, 0b1u8, 0b0u8] {
        'O'
    } else if bit_vec == [0b0u8, 0b0u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8] {
        'P'
    } else if bit_vec == [0b0u8, 0b1u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8] {
        'Q'
    } else if bit_vec == [0b0u8, 0b1u8, 0b0u8, 0b0u8, 0b0u8, 0b1u8] {
        'R'
    } else if bit_vec == [0b0u8, 0b1u8, 0b0u8, 0b0u8, 0b1u8, 0b0u8] {
        'S'
    } else if bit_vec == [0b0u8, 0b1u8, 0b0u8, 0b0u8, 0b1u8, 0b1u8] {
        'T'
    } else if bit_vec == [0b0u8, 0b1u8, 0b0u8, 0b1u8, 0b0u8, 0b0u8] {
        'U'
    } else if bit_vec == [0b0u8, 0b1u8, 0b0u8, 0b1u8, 0b0u8, 0b1u8] {
        'V'
    } else if bit_vec == [0b0u8, 0b1u8, 0b0u8, 0b1u8, 0b1u8, 0b0u8] {
        'W'
    } else if bit_vec == [0b0u8, 0b1u8, 0b0u8, 0b1u8, 0b1u8, 0b1u8] {
        'X'
    } else if bit_vec == [0b0u8, 0b1u8, 0b1u8, 0b0u8, 0b0u8, 0b0u8] {
        'Y'
    } else if bit_vec == [0b0u8, 0b1u8, 0b1u8, 0b0u8, 0b0u8, 0b1u8] {
        'Z'
    } else if bit_vec == [0b0u8, 0b1u8, 0b1u8, 0b0u8, 0b1u8, 0b0u8] {
        'a'
    } else if bit_vec == [0b0u8, 0b1u8, 0b1u8, 0b0u8, 0b1u8, 0b1u8] {
        'b'
    } else if bit_vec == [0b0u8, 0b1u8, 0b1u8, 0b1u8, 0b0u8, 0b0u8] {
        'c'
    } else if bit_vec == [0b0u8, 0b1u8, 0b1u8, 0b1u8, 0b0u8, 0b1u8] {
        'd'
    } else if bit_vec == [0b0u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b0u8] {
        'e'
    } else if bit_vec == [0b0u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8] {
        'f'
    } else if bit_vec == [0b1u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8] {
        'g'
    } else if bit_vec == [0b1u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b1u8] {
        'h'
    } else if bit_vec == [0b1u8, 0b0u8, 0b0u8, 0b0u8, 0b1u8, 0b0u8] {
        'i'
    } else if bit_vec == [0b1u8, 0b0u8, 0b0u8, 0b0u8, 0b1u8, 0b1u8] {
        'j'
    } else if bit_vec == [0b1u8, 0b0u8, 0b0u8, 0b1u8, 0b0u8, 0b0u8] {
        'k'
    } else if bit_vec == [0b1u8, 0b0u8, 0b0u8, 0b1u8, 0b0u8, 0b1u8] {
        'l'
    } else if bit_vec == [0b1u8, 0b0u8, 0b0u8, 0b1u8, 0b1u8, 0b0u8] {
        'm'
    } else if bit_vec == [0b1u8, 0b0u8, 0b0u8, 0b1u8, 0b1u8, 0b1u8] {
        'n'
    } else if bit_vec == [0b1u8, 0b0u8, 0b1u8, 0b0u8, 0b0u8, 0b0u8] {
        'o'
    } else if bit_vec == [0b1u8, 0b0u8, 0b1u8, 0b0u8, 0b0u8, 0b1u8] {
        'p'
    } else if bit_vec == [0b1u8, 0b0u8, 0b1u8, 0b0u8, 0b1u8, 0b0u8] {
        'q'
    } else if bit_vec == [0b1u8, 0b0u8, 0b1u8, 0b0u8, 0b1u8, 0b1u8] {
        'r'
    } else if bit_vec == [0b1u8, 0b0u8, 0b1u8, 0b1u8, 0b0u8, 0b0u8] {
        's'
    } else if bit_vec == [0b1u8, 0b0u8, 0b1u8, 0b1u8, 0b0u8, 0b1u8] {
        't'
    } else if bit_vec == [0b1u8, 0b0u8, 0b1u8, 0b1u8, 0b1u8, 0b0u8] {
        'u'
    } else if bit_vec == [0b1u8, 0b0u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8] {
        'v'
    } else if bit_vec == [0b1u8, 0b1u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8] {
        'w'
    } else if bit_vec == [0b1u8, 0b1u8, 0b0u8, 0b0u8, 0b0u8, 0b1u8] {
        'x'
    } else if bit_vec == [0b1u8, 0b1u8, 0b0u8, 0b0u8, 0b1u8, 0b0u8] {
        'y'
    } else if bit_vec == [0b1u8, 0b1u8, 0b0u8, 0b0u8, 0b1u8, 0b1u8] {
        'z'
    } else if bit_vec == [0b1u8, 0b1u8, 0b0u8, 0b1u8, 0b0u8, 0b0u8] {
        '0'
    } else if bit_vec == [0b1u8, 0b1u8, 0b0u8, 0b1u8, 0b0u8, 0b1u8] {
        '1'
    } else if bit_vec == [0b1u8, 0b1u8, 0b0u8, 0b1u8, 0b1u8, 0b0u8] {
        '2'
    } else if bit_vec == [0b1u8, 0b1u8, 0b0u8, 0b1u8, 0b1u8, 0b1u8] {
        '3'
    } else if bit_vec == [0b1u8, 0b1u8, 0b1u8, 0b0u8, 0b0u8, 0b0u8] {
        '4'
    } else if bit_vec == [0b1u8, 0b1u8, 0b1u8, 0b0u8, 0b0u8, 0b1u8] {
        '5'
    } else if bit_vec == [0b1u8, 0b1u8, 0b1u8, 0b0u8, 0b1u8, 0b0u8] {
        '6'
    } else if bit_vec == [0b1u8, 0b1u8, 0b1u8, 0b0u8, 0b1u8, 0b1u8] {
        '7'
    } else if bit_vec == [0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b0u8, 0b0u8] {
        '8'
    } else if bit_vec == [0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b0u8, 0b1u8] {
        '9'
    } else if bit_vec == [0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b0u8] {
        '+'
    } else if bit_vec == [0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8] {
        '/'
    } else {
        panic!("Received a u8 I cannot handle: {:?}", bit_vec)
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
        assert_eq!(
            hex_to_bytes("10ff00"),
            vec![0b00010000u8, 0b11111111u8, 0b00000000u8]
        );
    }

    #[test]
    fn test_bits_to_hex() {
        assert_eq!(bits_to_hex(&[0b0u8, 0b0u8, 0b0u8, 0b0u8]), "0");
        assert_eq!(
            bits_to_hex(&[0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8]),
            "00"
        );
        assert_eq!(
            bits_to_hex(&[
                0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8
            ]),
            "f00"
        );
        assert_eq!(
            bits_to_hex(&[
                0b1u8, 0b0u8, 0b1u8, 0b1u8, 0b1u8, 0b0u8, 0b1u8, 0b0u8, 0b0u8, 0b1u8, 0b1u8, 0b1u8
            ]),
            "ba7"
        );
    }

    #[test]
    fn test_hex_to_bits() {
        assert_eq!(hex_to_bits("0"), vec![0b0u8, 0b0u8, 0b0u8, 0b0u8]);
        assert_eq!(hex_to_bits("1"), vec![0b0u8, 0b0u8, 0b0u8, 0b1u8]);
        assert_eq!(hex_to_bits("f"), vec![0b1u8, 0b1u8, 0b1u8, 0b1u8]);
        assert_eq!(
            hex_to_bits("f0"),
            vec![0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8]
        );
        assert_eq!(
            hex_to_bits("ff"),
            vec![0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8]
        );
        assert_eq!(
            hex_to_bits("1f"),
            vec![0b0u8, 0b0u8, 0b0u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8]
        );
        assert_eq!(
            hex_to_bits("f1"),
            vec![0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b0u8, 0b0u8, 0b0u8, 0b1u8]
        );
        assert_eq!(
            hex_to_bits("a5"),
            vec![0b1u8, 0b0u8, 0b1u8, 0b0u8, 0b0u8, 0b1u8, 0b0u8, 0b1u8]
        );
        assert_eq!(
            hex_to_bits("5a"),
            vec![0b0u8, 0b1u8, 0b0u8, 0b1u8, 0b1u8, 0b0u8, 0b1u8, 0b0u8]
        );
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
        assert_eq!(vec![0b0u8], bits_xor(&[0b0u8], &[0b0u8]));
        assert_eq!(vec![0b0u8], bits_xor(&[0b1u8], &[0b1u8]));
        assert_eq!(vec![0b1u8], bits_xor(&[0b0u8], &[0b1u8]));

        assert_eq!(
            vec![0b0u8, 0b0u8, 0b0u8],
            bits_xor(&[0b0u8, 0b1u8, 0b1u8], &[0b0u8, 0b1u8, 0b1u8])
        );
        assert_eq!(
            vec![0b1u8, 0b1u8, 0b1u8],
            bits_xor(&[0b0u8, 0b1u8, 0b1u8], &[0b1u8, 0b0u8, 0b0u8])
        );

        assert_eq!(
            vec![0b1u8, 0b1u8, 0b1u8, 0b0u8],
            bits_xor(&[0b1u8, 0b1u8, 0b0u8], &[0b1u8, 0b0u8, 0b0u8, 0b0u8])
        );
    }

    #[test]
    fn test_bits_to_u8() {
        assert_eq!(0, bits_to_u8(&[0b0u8]));
        assert_eq!(0, bits_to_u8(&[0b0u8, 0b0u8]));
        assert_eq!(1, bits_to_u8(&[0b1u8]));
        assert_eq!(2, bits_to_u8(&[0b1u8, 0b0u8]));
        assert_eq!(1, bits_to_u8(&[0b0u8, 0b1u8]));
        assert_eq!(2, bits_to_u8(&[0b0u8, 0b1u8, 0b0u8]));
        assert_eq!(6, bits_to_u8(&[0b1u8, 0b1u8, 0b0u8]));
        assert_eq!(7, bits_to_u8(&[0b1u8, 0b1u8, 0b1u8]));
        assert_eq!(
            118,
            bits_to_u8(&[0b0u8, 0b1u8, 0b1u8, 0b1u8, 0b0u8, 0b1u8, 0b1u8, 0b0u8])
        );
        assert_eq!(
            255,
            bits_to_u8(&[0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8])
        );
    }

    #[test]
    fn test_u8_to_bits() {
        assert_eq!(
            u8_to_bits(0b00000000u8),
            [0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8]
        );
        assert_eq!(
            u8_to_bits(0b11111111u8),
            [0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8]
        );
        assert_eq!(
            u8_to_bits(0b00000001u8),
            [0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b1u8]
        );
        assert_eq!(
            u8_to_bits(0b10000000u8),
            [0b1u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8]
        );
        assert_eq!(
            u8_to_bits(0b11000010u8),
            [0b1u8, 0b1u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b1u8, 0b0u8]
        );
        assert_eq!(
            u8_to_bits(0b00000010u8),
            [0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b1u8, 0b0u8]
        );
        assert_eq!(
            u8_to_bits(0b00010000u8),
            [0b0u8, 0b0u8, 0b0u8, 0b1u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8]
        );
    }

    #[test]
    fn test_bits_xor_expiremental() {
        assert_eq!(1u8, 0b00000001u8);
        assert_eq!(1, 0b00000001u8);
        assert_eq!(1, 0b1u8);
        assert_eq!(1, 0b1);
        assert_eq!(0b1, 0b1 | 0b1);
        assert_eq!(0b0, 0b1 ^ 0b1);
        assert_eq!(0b1, 0b1 & 0b1);
        assert_eq!(0b0, 0b0 & 0b1);
        assert_eq!(0b11111111, 0b00000000 ^ 0b11111111);
        assert_eq!(0b00000000, 0b00000000 & 0b11111111);
        assert_eq!(0b01010101, 0b10101010 ^ 0b11111111);
    }
}
