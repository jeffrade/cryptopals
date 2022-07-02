use std::fs::File;
use std::io::{prelude::*, BufReader};

use crate::util::*;

pub fn challenges() {
    challenge_1(); // https://cryptopals.com/sets/1/challenges/1
    challenge_2(); // https://cryptopals.com/sets/1/challenges/2
    challenge_3(); // https://cryptopals.com/sets/1/challenges/3
    challenge_4(); // https://cryptopals.com/sets/1/challenges/4
    challenge_5(); // https://cryptopals.com/sets/1/challenges/5
}

// https://en.wikipedia.org/wiki/Hexadecimal
// https://en.wikipedia.org/wiki/Base64
fn challenge_1() {
    assert_eq!(
        hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"),
        String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
    );
}

// https://www.binaryhexconverter.com/hex-to-binary-converter
// http://www.xor.pw
fn challenge_2() {
    assert_eq!(
        hex_xor(
            "1c0111001f010100061a024b53535009181c",
            "686974207468652062756c6c277320657965"
        ),
        String::from("746865206b696420646f6e277420706c6179")
    );
}

// https://en.wikipedia.org/wiki/Letter_frequency
fn challenge_3() {
    let cipher_text: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    find_single_byte_key(cipher_text, true);
}

// "Now that the party is jumping"
fn challenge_4() {
    let file = File::open("challenge-data/4.txt").unwrap();
    let reader = BufReader::new(file);

    for line in reader.lines() {
        find_single_byte_key(&line.unwrap(), true);
    }
}

fn challenge_5() {
    let stanza_plaintext =
        "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let symmetric_key = "ICE";
    let ciphertext = repeating_key_xor(stanza_plaintext, symmetric_key);
    assert_eq!(
        ciphertext,
        String::from("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
    );
}

fn repeating_key_xor(plaintext: &str, key: &str) -> String {
    let mut ciphertext_bytes = Vec::<u8>::new();
    let plaintext_bytes = plaintext.as_bytes();
    let key_bytes = key.as_bytes();
    let key_length = key_bytes.len();
    let mut key_index = 0;

    for plaintext_byte in plaintext_bytes {
        if key_index == key_length {
            key_index = 0;
        }

        let xored = plaintext_byte ^ key_bytes[key_index];
        ciphertext_bytes.push(xored);

        key_index += 1;
    }

    bytes_to_hex(&ciphertext_bytes)
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
        let ch_count = plaintext_up.find(|c: char| &c == ch).unwrap_or(0);
        percents.push(ch_count as f32 / str_len as f32);
    }

    percents
}
