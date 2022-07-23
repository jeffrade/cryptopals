use std::fs::File;
use std::io::{prelude::*, BufReader};
use std::slice::ChunksExact;

use crate::util::*;

pub fn start() {
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
    fn test_find_single_byte_key() {
        // https://www.xor.pw/#
        assert_eq!(find_single_byte_key(&hex_to_bytes("42162a2b31622b3162236236273136622d2462362a2762272f273025272c213b6220302d23262123313662313b3136272f6c"), true), 66);
    }
}
