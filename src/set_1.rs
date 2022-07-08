use std::fs::File;
use std::io::{prelude::*, BufReader};
use std::slice::ChunksExact;

use crate::util::*;

pub fn challenges() {
    challenge_1(); // https://cryptopals.com/sets/1/challenges/1
    challenge_2(); // https://cryptopals.com/sets/1/challenges/2
    challenge_3(); // https://cryptopals.com/sets/1/challenges/3
    challenge_4(); // https://cryptopals.com/sets/1/challenges/4
    challenge_5(); // https://cryptopals.com/sets/1/challenges/5
    challenge_6(); // https://cryptopals.com/sets/1/challenges/6
}

// https://en.wikipedia.org/wiki/Hexadecimal
// https://en.wikipedia.org/wiki/Base64
fn challenge_1() {
    println!("Starting Set 1, Challenge 1...");
    assert_eq!(
        hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"),
        String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
    );
    println!("Done!")
}

// https://www.binaryhexconverter.com/hex-to-binary-converter
// http://www.xor.pw
fn challenge_2() {
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

// https://en.wikipedia.org/wiki/Letter_frequency
fn challenge_3() {
    println!("Starting Set 1, Challenge 3...");
    let ciphertext: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let ciphertext_bytes = hex_to_bytes(ciphertext);
    let key = find_single_byte_key(&ciphertext_bytes, true);
    let xored: Vec<u8> = bytes_xor(&ciphertext_bytes, &vec![key; ciphertext_bytes.len()]);
    let plaintext = String::from_utf8_lossy(&xored);
    println!("{} deciphered to plaintext {}", key, plaintext);
}

fn challenge_4() {
    println!("Starting Set 1, Challenge 4...");
    let file = File::open("challenge-data/4.txt").unwrap();
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let ciphertext_bytes = hex_to_bytes(&line.unwrap());
        let key = find_single_byte_key(&ciphertext_bytes, true);
        let xored: Vec<u8> = bytes_xor(&ciphertext_bytes, &vec![key; ciphertext_bytes.len()]);
        let plaintext = String::from_utf8_lossy(&xored);
        if resembles_english(&plaintext) {
            println!("{} deciphered to plaintext {}", key, plaintext);
        }
    }
}

fn challenge_5() {
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

fn challenge_6() {
    println!("Starting Set 1, Challenge 6...");
    let file = File::open("challenge-data/6.txt").unwrap();
    let reader = BufReader::new(file);
    let mut ciphertext = Vec::<u8>::new();
    for line in reader.lines() {
        ciphertext.append(&mut hex_to_bytes(&base64_to_hex(&line.unwrap())));
    }

    let key_sizes = top_keysizes(&ciphertext, 2, 40);
    for key_size in key_sizes {
        let key_parts = get_potential_key_parts(key_size, &ciphertext, false);
        let mut full_key: Vec<u8> = Vec::new();
        for (_, v) in key_parts.iter().enumerate() {
            full_key.push(*v);
        }
        println!(
            "Attempting to decrypt with key={}",
            String::from_utf8_lossy(&full_key)
        );
        let plaintext = repeating_key_xor_bytes(&ciphertext, &full_key);
        if let Ok(text) = String::from_utf8(plaintext) {
            if resembles_english(&text) {
                println!("DECIPHERED?\n{}", &text);
            }
        }
    }
}

fn get_potential_key_parts(keysize: i32, ciphertext: &[u8], visual: bool) -> Vec<u8> {
    let tblocks: Vec<Vec<u8>> = transpose_blocks_by_size(keysize as usize, ciphertext);
    let mut key_parts: Vec<u8> = Vec::new();
    for (_, block) in tblocks.iter().enumerate() {
        let key = find_single_byte_key(block, false);
        if visual {
            let xored: Vec<u8> = bytes_xor(block, &vec![key; block.len()]);
            if let Ok(plaintext) = String::from_utf8(xored) {
                // Let's see if there is anything close to an english word, sentence, etc.
                println!("{} deciphered to plaintext {}", key, plaintext);
            }
        }
        key_parts.push(key);
    }
    key_parts
}

fn resembles_english(plaintext: &str) -> bool {
    // Try different patterns to see if we are close to the english language
    //FIXME Build a few simple regex's
    plaintext.to_lowercase().contains(" the ")
        && plaintext.to_lowercase().contains(" a ")
        && plaintext.contains(". ")
        || plaintext.contains(". The")
        || (plaintext.contains(" of ") && plaintext.contains(" the "))
        || (plaintext.contains(" is ") && plaintext.contains(" of "))
        || plaintext.contains(" this ")
        || plaintext.contains(" that ")
}

fn top_keysizes(ciphertext: &[u8], min: i32, max: i32) -> Vec<i32> {
    let mut k = min;
    let mut keysizes = Vec::<i32>::new();
    while k <= max {
        // Let's choose 3.0 after seeing most key lengths are above this threshold.
        if calc_distances(k, ciphertext) < 3.0_f32 {
            keysizes.push(k);
        }
        k += 1;
    }
    keysizes
}

fn calc_distances(keysize: i32, ciphertext: &[u8]) -> f32 {
    let index_pivot = keysize as usize;
    let first_chunk: &[u8] = &ciphertext[0..index_pivot];
    let second_chunk: &[u8] = &ciphertext[index_pivot..(2 * index_pivot)];
    let third_chunk: &[u8] = &ciphertext[(2 * index_pivot)..(3 * index_pivot)];
    let fourth_chunk: &[u8] = &ciphertext[(3 * index_pivot)..(4 * index_pivot)];
    let hamm_dist_1 = hamming_distance(first_chunk, second_chunk);
    let hamm_dist_2 = hamming_distance(second_chunk, third_chunk);
    let hamm_dist_3 = hamming_distance(third_chunk, fourth_chunk);
    let hamm_dist_avg = (hamm_dist_1 + hamm_dist_2 + hamm_dist_3) as f32 / 3.0;
    let normalized_dist: f32 = hamm_dist_avg / (keysize as f32);
    println!(
        "normalized hamming distance {} for keysize {}",
        normalized_dist, keysize
    );
    normalized_dist
}

fn is_text(x: &u8) -> bool {
    *x >= 65_u8 && *x <= 122_u8 || *x == 32_u8
}

fn repeating_key_xor(input: &str, key: &str) -> Vec<u8> {
    repeating_key_xor_bytes(input.as_bytes(), key.as_bytes())
}

fn repeating_key_xor_bytes(input: &[u8], key: &[u8]) -> Vec<u8> {
    let mut output = Vec::<u8>::new();
    let key_length = key.len();
    let mut key_index = 0;

    for input_byte in input {
        if key_index == key_length {
            key_index = 0;
        }

        let xored = input_byte ^ key[key_index];
        output.push(xored);

        key_index += 1;
    }

    output
}

fn find_single_byte_key(ciphertext_bytes: &[u8], detect_english: bool) -> u8 {
    let mut best_guess: u8 = 0;
    let mut max_count: i32 = 0;
    for i in 32..=126 {
        let key_guess = vec![i; ciphertext_bytes.len()];
        let xored: Vec<u8> = bytes_xor(ciphertext_bytes, &key_guess);
        let text_count = xored
            .iter()
            .fold(0, |acc, x| if is_text(x) { acc + 1 } else { acc });

        let mut english_ish = true;
        if detect_english {
            let plaintext = String::from_utf8_lossy(&xored);
            english_ish = english_analysis_hit(&plaintext, 1.0);
        }
        if english_ish && text_count > max_count {
            max_count = text_count;
            best_guess = i;
        }
    }
    best_guess
}

fn english_analysis_hit(plaintext: &str, multiplier: f32) -> bool {
    // Let's just do something simple for now to only show most likely plaintexts.
    if !plaintext.is_ascii() {
        return false;
    }
    let percentages = char_analysis_counts(plaintext);
    let e_per: f32 = percentages[0];
    let t_per: f32 = percentages[1];
    let a_per: f32 = percentages[2];
    let o_per: f32 = percentages[3];
    let i_per: f32 = percentages[4];
    let n_per: f32 = percentages[5];
    let s_per: f32 = percentages[6];
    let h_per: f32 = percentages[7];
    let r_per: f32 = percentages[8];
    let d_per: f32 = percentages[9];
    let l_per: f32 = percentages[10];
    let u_per: f32 = percentages[11];
    let space_per: f32 = percentages[12];

    (e_per > multiplier * 0.13
        || t_per > multiplier * 0.091
        || a_per > multiplier * 0.082
        || o_per > multiplier * 0.075
        || i_per > multiplier * 0.07
        || n_per > multiplier * 0.067
        || s_per > multiplier * 0.063
        || h_per > multiplier * 0.061
        || r_per > multiplier * 0.06
        || d_per > multiplier * 0.043
        || l_per > multiplier * 0.04
        || u_per > multiplier * 0.028)
        && space_per > multiplier * 0.07
}

fn char_analysis_counts(plaintext: &str) -> Vec<f32> {
    const FREQ_CHARS: [char; 13] = [
        'E', 'T', 'A', 'O', 'I', 'N', 'S', 'H', 'R', 'D', 'L', 'U', ' ',
    ];
    let mut percents: Vec<f32> = Vec::new();
    let str_len = plaintext.chars().count();
    let plaintext_up: String = plaintext.to_uppercase();
    for ch in FREQ_CHARS.iter() {
        let ch_count = plaintext_up.find(|c: char| &c == ch).unwrap_or(0);
        percents.push(ch_count as f32 / str_len as f32);
    }

    percents
}

fn transpose_blocks_by_size(blocksize: usize, input: &[u8]) -> Vec<Vec<u8>> {
    let chunks: ChunksExact<u8> = input.chunks_exact(blocksize);
    let mut blocks: Vec<Vec<u8>> = Vec::<Vec<u8>>::new();

    // initialize empty transposed blocks
    for _ in 0..blocksize {
        let v: Vec<u8> = Vec::new();
        blocks.push(v);
    }

    for chunk in chunks {
        for (jth_byte, byte) in chunk.iter().enumerate() {
            blocks.get_mut(jth_byte).unwrap().push(*byte);
        }
    }

    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transpose_blocks() {
        let ciphertext = vec![
            0b0001u8, 0b0010u8, 0b0011u8, 0b0100u8, 0b0101u8, 0b0110u8, 0b0111u8, 0b1000u8,
            0b1001u8, 0b1010u8, 0b1011u8, 0b1100u8, 0b1101u8,
        ];
        let actual: Vec<Vec<u8>> = transpose_blocks_by_size(4 as usize, &ciphertext);
        let expected: Vec<Vec<u8>> = vec![
            vec![1, 5, 9],
            vec![2, 6, 10],
            vec![3, 7, 11],
            vec![4, 8, 12],
        ];
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_is_text() {
        assert_eq!(is_text(&31_u8), false);
        assert_eq!(is_text(&32_u8), true);
        assert_eq!(is_text(&33_u8), false);
        assert_eq!(is_text(&3_u8), false);
        assert_eq!(is_text(&122_u8), true);
        assert_eq!(is_text(&123_u8), false);
    }

    #[test]
    fn test_find_single_byte_key() {
        // https://www.xor.pw/#
        assert_eq!(find_single_byte_key(&hex_to_bytes("42162a2b31622b3162236236273136622d2462362a2762272f273025272c213b6220302d23262123313662313b3136272f6c"), true), 66);
    }
}
