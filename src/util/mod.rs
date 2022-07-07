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

pub fn base64_to_hex(s: &str) -> String {
    let snp = s.replace('=', "");
    let padding_count = s.len() - snp.len();
    let bits6: Vec<[u8; 6]> = snp.chars().map(b64_to_six_bits).collect();
    let mut bits: Vec<u8> = Vec::new();
    for b6 in bits6 {
        for b in b6 {
            bits.push(b);
        }
    }

    if padding_count <= 2 {
        bits.truncate(bits.len() - 2 * padding_count);
    } else {
        panic!("padding_count is phucked!");
    }

    bits_to_hex(bits.as_slice())
}

pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    let hex_chars: Vec<char> = hex.chars().collect();
    let hex_bytes = hex_chars.chunks_exact(2);
    let remainder: &[char] = hex_bytes.remainder();

    if hex.len() % 2 != 0 || !remainder.is_empty() {
        println!("WARNING: hex_to_bytes({}): remainder={:?}", hex, remainder); //TODO Something might need 0 padded prefix (write test cases) or information loss.
    }

    for hex_byte in hex_bytes {
        bytes.push(hex_to_byte(hex_byte));
    }

    bytes
}

pub fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    let xored = bytes_xor(a, b);
    hamming_weight(xored)
}

fn hamming_weight(v: Vec<u8>) -> u32 {
    *v.iter()
        .map(|&x| x.count_ones())
        .reduce(|acc, y| acc + y)
        .get_or_insert(0)
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

fn b64_to_six_bits(c: char) -> [u8; 6] {
    if c == 'A' {
        [0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8]
    } else if c == 'B' {
        [0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b1u8]
    } else if c == 'C' {
        [0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b1u8, 0b0u8]
    } else if c == 'D' {
        [0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b1u8, 0b1u8]
    } else if c == 'E' {
        [0b0u8, 0b0u8, 0b0u8, 0b1u8, 0b0u8, 0b0u8]
    } else if c == 'F' {
        [0b0u8, 0b0u8, 0b0u8, 0b1u8, 0b0u8, 0b1u8]
    } else if c == 'G' {
        [0b0u8, 0b0u8, 0b0u8, 0b1u8, 0b1u8, 0b0u8]
    } else if c == 'H' {
        [0b0u8, 0b0u8, 0b0u8, 0b1u8, 0b1u8, 0b1u8]
    } else if c == 'I' {
        [0b0u8, 0b0u8, 0b1u8, 0b0u8, 0b0u8, 0b0u8]
    } else if c == 'J' {
        [0b0u8, 0b0u8, 0b1u8, 0b0u8, 0b0u8, 0b1u8]
    } else if c == 'K' {
        [0b0u8, 0b0u8, 0b1u8, 0b0u8, 0b1u8, 0b0u8]
    } else if c == 'L' {
        [0b0u8, 0b0u8, 0b1u8, 0b0u8, 0b1u8, 0b1u8]
    } else if c == 'M' {
        [0b0u8, 0b0u8, 0b1u8, 0b1u8, 0b0u8, 0b0u8]
    } else if c == 'N' {
        [0b0u8, 0b0u8, 0b1u8, 0b1u8, 0b0u8, 0b1u8]
    } else if c == 'O' {
        [0b0u8, 0b0u8, 0b1u8, 0b1u8, 0b1u8, 0b0u8]
    } else if c == 'P' {
        [0b0u8, 0b0u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8]
    } else if c == 'Q' {
        [0b0u8, 0b1u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8]
    } else if c == 'R' {
        [0b0u8, 0b1u8, 0b0u8, 0b0u8, 0b0u8, 0b1u8]
    } else if c == 'S' {
        [0b0u8, 0b1u8, 0b0u8, 0b0u8, 0b1u8, 0b0u8]
    } else if c == 'T' {
        [0b0u8, 0b1u8, 0b0u8, 0b0u8, 0b1u8, 0b1u8]
    } else if c == 'U' {
        [0b0u8, 0b1u8, 0b0u8, 0b1u8, 0b0u8, 0b0u8]
    } else if c == 'V' {
        [0b0u8, 0b1u8, 0b0u8, 0b1u8, 0b0u8, 0b1u8]
    } else if c == 'W' {
        [0b0u8, 0b1u8, 0b0u8, 0b1u8, 0b1u8, 0b0u8]
    } else if c == 'X' {
        [0b0u8, 0b1u8, 0b0u8, 0b1u8, 0b1u8, 0b1u8]
    } else if c == 'Y' {
        [0b0u8, 0b1u8, 0b1u8, 0b0u8, 0b0u8, 0b0u8]
    } else if c == 'Z' {
        [0b0u8, 0b1u8, 0b1u8, 0b0u8, 0b0u8, 0b1u8]
    } else if c == 'a' {
        [0b0u8, 0b1u8, 0b1u8, 0b0u8, 0b1u8, 0b0u8]
    } else if c == 'b' {
        [0b0u8, 0b1u8, 0b1u8, 0b0u8, 0b1u8, 0b1u8]
    } else if c == 'c' {
        [0b0u8, 0b1u8, 0b1u8, 0b1u8, 0b0u8, 0b0u8]
    } else if c == 'd' {
        [0b0u8, 0b1u8, 0b1u8, 0b1u8, 0b0u8, 0b1u8]
    } else if c == 'e' {
        [0b0u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b0u8]
    } else if c == 'f' {
        [0b0u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8]
    } else if c == 'g' {
        [0b1u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8]
    } else if c == 'h' {
        [0b1u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8, 0b1u8]
    } else if c == 'i' {
        [0b1u8, 0b0u8, 0b0u8, 0b0u8, 0b1u8, 0b0u8]
    } else if c == 'j' {
        [0b1u8, 0b0u8, 0b0u8, 0b0u8, 0b1u8, 0b1u8]
    } else if c == 'k' {
        [0b1u8, 0b0u8, 0b0u8, 0b1u8, 0b0u8, 0b0u8]
    } else if c == 'l' {
        [0b1u8, 0b0u8, 0b0u8, 0b1u8, 0b0u8, 0b1u8]
    } else if c == 'm' {
        [0b1u8, 0b0u8, 0b0u8, 0b1u8, 0b1u8, 0b0u8]
    } else if c == 'n' {
        [0b1u8, 0b0u8, 0b0u8, 0b1u8, 0b1u8, 0b1u8]
    } else if c == 'o' {
        [0b1u8, 0b0u8, 0b1u8, 0b0u8, 0b0u8, 0b0u8]
    } else if c == 'p' {
        [0b1u8, 0b0u8, 0b1u8, 0b0u8, 0b0u8, 0b1u8]
    } else if c == 'q' {
        [0b1u8, 0b0u8, 0b1u8, 0b0u8, 0b1u8, 0b0u8]
    } else if c == 'r' {
        [0b1u8, 0b0u8, 0b1u8, 0b0u8, 0b1u8, 0b1u8]
    } else if c == 's' {
        [0b1u8, 0b0u8, 0b1u8, 0b1u8, 0b0u8, 0b0u8]
    } else if c == 't' {
        [0b1u8, 0b0u8, 0b1u8, 0b1u8, 0b0u8, 0b1u8]
    } else if c == 'u' {
        [0b1u8, 0b0u8, 0b1u8, 0b1u8, 0b1u8, 0b0u8]
    } else if c == 'v' {
        [0b1u8, 0b0u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8]
    } else if c == 'w' {
        [0b1u8, 0b1u8, 0b0u8, 0b0u8, 0b0u8, 0b0u8]
    } else if c == 'x' {
        [0b1u8, 0b1u8, 0b0u8, 0b0u8, 0b0u8, 0b1u8]
    } else if c == 'y' {
        [0b1u8, 0b1u8, 0b0u8, 0b0u8, 0b1u8, 0b0u8]
    } else if c == 'z' {
        [0b1u8, 0b1u8, 0b0u8, 0b0u8, 0b1u8, 0b1u8]
    } else if c == '0' {
        [0b1u8, 0b1u8, 0b0u8, 0b1u8, 0b0u8, 0b0u8]
    } else if c == '1' {
        [0b1u8, 0b1u8, 0b0u8, 0b1u8, 0b0u8, 0b1u8]
    } else if c == '2' {
        [0b1u8, 0b1u8, 0b0u8, 0b1u8, 0b1u8, 0b0u8]
    } else if c == '3' {
        [0b1u8, 0b1u8, 0b0u8, 0b1u8, 0b1u8, 0b1u8]
    } else if c == '4' {
        [0b1u8, 0b1u8, 0b1u8, 0b0u8, 0b0u8, 0b0u8]
    } else if c == '5' {
        [0b1u8, 0b1u8, 0b1u8, 0b0u8, 0b0u8, 0b1u8]
    } else if c == '6' {
        [0b1u8, 0b1u8, 0b1u8, 0b0u8, 0b1u8, 0b0u8]
    } else if c == '7' {
        [0b1u8, 0b1u8, 0b1u8, 0b0u8, 0b1u8, 0b1u8]
    } else if c == '8' {
        [0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b0u8, 0b0u8]
    } else if c == '9' {
        [0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b0u8, 0b1u8]
    } else if c == '+' {
        [0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b0u8]
    } else if c == '/' {
        [0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8, 0b1u8]
    } else {
        panic!("Received a char I cannot handle: {:?}", c)
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
    fn test_base64_to_hex_without_padding() {
        // https://base64.guru/converter/decode/hex
        assert_eq!(base64_to_hex("Rm9vYmFy"), String::from("466f6f626172"));
        assert_eq!(base64_to_hex("TWFu"), String::from("4d616e"));
        assert_eq!(base64_to_hex("egwA"), String::from("7a0c00"));
    }

    #[test]
    fn test_base64_to_hex_with_padding() {
        // https://base64.guru/converter/decode/hex
        assert_eq!(base64_to_hex("TQ=="), String::from("4d"));
        assert_eq!(base64_to_hex("TWE="), String::from("4d61"));
        assert_eq!(
            base64_to_hex("QWxhbiBUdXJpbmc="),
            String::from("416c616e20547572696e67")
        );
        assert_eq!(
            base64_to_hex(BASE64_INPUT.replace('\n', "").as_str()),
            String::from(BASE64_TO_HEX_EXPECTED)
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

    #[test]
    fn test_hamming_distance_strings() {
        let a = "this is a test";
        let b = "wokka wokka!!!";
        assert_eq!(hamming_distance(a.as_bytes(), b.as_bytes()), 37);
    }

    const BASE64_INPUT: &str = r"
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
";
    const BASE64_TO_HEX_EXPECTED: &str = "1d421f4d0b0f021f4f134e3c1a69651f491c0e4e13010b074e1b01164536001e01496420541d1d4333534e6552060047541c0d454d07040c53123c0c1e08491a09114f144c211a472b00051d47591104090064260753003716060c1a17411d015254305f0020130a05474f124808454e653e160938450605081a46074f1f59787e6a62360c1d0f410d4806551a1b001d4274041e01491a091102527a7f4900483a001a13491a4f45480f1d0d53043a015219010b411306004c315f53621506070907540b17411416497933350b1b01050f46074f1d4e784e48275204070c4558480841004f205408740b1d194902000e165c00523069651f4902025400010b074e021053012610154d0207021f4f1b4e78306936520a010954060709534e021053083b100605490f0f104f3b003a5f472b1c4964334f540210531a4f051611740c064d0f020e0343524c3d4e002f0b490d084e170d15541d4f0e1c455e280b4d190112070a5553784e4f6206010b47531d0c0000170a051f0c3a425e4d2e0141220e1c493456416235064f472a7e3b084f011b0153423704071e0c4e151c0e06072b1a542a17491906595421455707030553073145782c070a411d095259374f00261d07491300130113454e0e491704390b5e4d1d06041a4f78773043003b1d1c4e1454151a0c4e494f080745390052673a0141130a0600375c4662550a0f125311482c000d000707173b095219010b41071b13473d1a2a161a0c1c020707480b4f4e0b0000163d0b554d08020d1b181744783069651f490709001911454f190149030d3516174d633a09114f15492a56492701491d06000d4811480b16491f0a220052000c4e001a0b5254305b54621b1a4e084b5462244e0a4f205306350b5209080002114f10452c4e4530521d06064e54090b594e040017453a42521d050f18546578732c5b4727525b4e4a0d543100414e1b0116453b0b174d100f465418134e365b002e1b1a1a024e541c0a0064261d5416740a140b490318540717413c1a532d52050b1300000000000c0a08074524091314491a0906000747301a2a111d49274743150645461b0102530c2045071d490f0f104f1f41335f002b06491d08551a0c454701000d536f654840405a4e381b4f5f0d78714e2d11024e084e541b0a4d0b4f1e1c0a3045782b061c4113001d447856552119454e2e0018010e454e021053173c1c1f081a4e00001d1d433155553152633d1250111a0641020e0f0104330c1e041a1a08170a0a50315b4c2b16060d0e4f011b452a27480453043a45170b0f0b02004f134e3c1a542a131d4e1e4f01480641004f0b1611746f3b4d0a0f0f541b134b3d1a416214051747471d1a09000f010d5308350e174d010b1354181754761a2a483b4e03474c1d0300003d0e04000a3a455f40493d00191c1d4e784e4f62360c020e4c1500452a3a070c010073165203064e0511010b49361d0c622b061b4743150645541c1649070a740d13030e4e6b361a0600215555651e054e0c45111845541c16001d4274111d4d0e0b1554020b002b4e592e1749642856111a4541000b491c1331175e4d191c00171b1b433d1a4d23190c1d4750111a03450d1b49792721115203061a411d095259374f073017490f474c1b0903451c4149796f0d0a074a050241130a06003655572a171b0b4b001a074550020e0a1649740b1d4d1d070c1143524e371a472b00051d472a27070a4e4e4244532a3c451f1449290e10435248375745201d0d174b000d0710001e1d06110436090b4d0c0f1554652150395d4827061d0747571d1c0d000f4f1a030a3b0b534d2a010c114f1d4e785b4e26521a0f1e001d1c440064653f3a357a45240c07070d180e52693b5f003b17194247591118490027480453063b081b034e4e09151d160034534b2752084e15481d060a00642607070a2c0c110c1d070f134f014f78434f37521a1a0647130d17000206021645354505040701417e3c1d00284f4e2901491d134f044811521706071445350b164d0e0713184f0154374a00210010070907546233410006051f04742c1108490712541c174c34534e6552080003000d0710001e0a0603093145131f0c4e0301161b4e7f1a2a6531081b1445541f0d594e1b0116453217170c021d41151d1700325543291b0749474c1d0300002d1d08091c74221e180c4e6b39000449361d00231c0d4e00521b07134900484907172d0c1c0a491a0e541c1b4e3f1a412e1d0709472a350409001a071b1c10330d5219010b41130717542c55002500060111491a4f455406061a530d3117174d1a010f134f786e374d003b1d1c49154554090841140a0d53072d4506050c4e373d3f5250374953275c49646d73000d155007014e53163b451a0c1b0a4118061945785b0005171b03064e5426045a074f632011351706010c0a4116165254305f0020131a0b14001c01115407014e5302260a07030d4e6b200717523d1d53621c064e13521d1815490048491c0b74081b030c42413d481f00324f5336520e0b13541d0642000a001e1d455e36020c1b0500190e06493b16000b55044e0f411a0f0c4e494f1d1a023c115201000504540e5246395441361b0a4e6d791b1d45541c0e19030030451f0849010f170a5241365e000b521d060855130011001a070807455e3c1d1849030813070600305b562752001a472a270745531a0a1953013b121c4d0800055403174e3c1a4d275210011252540d04524e654e4b5c740c1c4d04174100061f45791a792d07454e401944480c534e0210531c3104004349646b2d0007072a5f0035170805024e1d064200080e1a0749743c3d4c490f0f104f3b003b5b4e62060c020b001d1c452a37001c0145360a16144e1d41130a0654315407621a061a4b00070749001d00493a4537041c4d1a0304180352492c1a2a111d490a084e531c45420b4f04120174041c09490a0e1a4806003a5f0031130d4e6d07370910530b4f1d1b0074090b1f000d12540d174c3754476206064e2e6331444579011a4910043a45110c050241190a5264395e00482b061b4052114815491a0c011a0b7345134d0f0715584f014f7849542702490c06431f48044e0a4f0c1d012117174d632204004f06483d1a572b060a0647441b0b114f1c43493a0631495209064e151c0a524439544327521d014743011a0000643c0653063b08174d1c1e4117031d533d1a412c16490a084e531c45420b4f1a02103517174d63370e014f05413654416210081a134c114808454e424453243a1c0604040b4d540e1c592f5245301749646d791b1d455406001c140d20450605081a413d4f05412b1a572713024247621b11490017001c541731451608080a41031d1d4e3f1a2a111d490d084d11480a4e424f0c0500261c10020d1741150116002b534e25521d060e53541b0a4e094f637936351c5240444e31180e0b002c524136520f1b094b0d4808551d060a5336351c5e4d0e014103071b543d1a422d0b454e004f541f0d491a0a49110a2d451502496411180e0b002c524136520f1b094b0d4808551d060a53223b450505001a04540d1d59741a472d521e060e541148074f174349140a746f3e0c104e051b181c003954446210060100491148044e0a4f191f042d450605081a41121a1c4b211a4d3701000d47541d04090017001c53013d005c4d636431180e0b002c524136520f1b094b0d4808551d060a53263b08174d06004d542c1d4d3d1a4f2c5e4902025454050000060a0801455e351e0c104e151c0e06003e4f4e290b490312531d0b455706061d1645360a0b4d100114541c13597853546e521a0f1e001d1c452a3e03080a45200d13194908141a040b00354f532b11492f474c1d1c114c0b4f051c103000004d0701165465224c394300361a081a474601060e594e021c000c3749521a010715114f104f211a632d1f0c4e084e5848264f030a491c0b78453102040b411b01522a0856413b521d060654540e104e0516491e10270c114d63";
}
