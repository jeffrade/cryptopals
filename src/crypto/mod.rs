#![allow(clippy::upper_case_acronyms)]

pub mod aes;
pub mod util;

pub enum AesMode {
    ECB,
    CBC,
}

pub fn aes128_decrypt(ciphertext: &[u8], key: &[u8], mode: AesMode) -> Vec<u8> {
    match mode {
        AesMode::ECB => {
            if ciphertext.len() % 16 != 0 {
                panic!("Must supply ciphertext with size multiple of 16!");
            }
            let chunks: usize = ciphertext.len() / 16;
            let mut plaintext_bytes: Vec<u8> = Vec::new();
            for index in 0..chunks {
                let start: usize = index * 16;
                let end: usize = start + 16;
                plaintext_bytes.append(&mut aes::ecb_128_decrypt(&ciphertext[start..end], key));
            }
            plaintext_bytes
        }
        AesMode::CBC => {
            panic!("AES CBC mode not yet implemented!");
        }
    }
}

pub fn aes128_encrypt(plaintext: &[u8], key: &[u8], mode: AesMode) -> Vec<u8> {
    match mode {
        AesMode::ECB => {
            if plaintext.len() % 16 != 0 {
                panic!("Must supply ciphertext with size multiple of 16!");
            }
            let chunks: usize = plaintext.len() / 16;
            let mut ciphertext_bytes: Vec<u8> = Vec::new();
            for index in 0..chunks {
                let start: usize = index * 16;
                let end: usize = start + 16;
                ciphertext_bytes.append(&mut aes::ecb_128_encrypt(&plaintext[start..end], key));
            }
            ciphertext_bytes
        }
        AesMode::CBC => {
            panic!("AES CBC mode not yet implemented!");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_ecb_128_decrypt() {
        // https://github.com/kokke/tiny-AES-c/blob/12e7744b4919e9d55de75b7ab566326a1c8e7a67/test.c#L294-L299
        let key: &[u8; 16] = &[
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let ciphertext: &[u8; 16] = &[
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66,
            0xef, 0x97,
        ];
        assert_eq!(
            ciphertext,
            &[58, 215, 123, 180, 13, 122, 54, 96, 168, 158, 202, 243, 36, 102, 239, 151]
        );
        let expected: &[u8; 16] = &[
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        assert_eq!(aes::ecb_128_decrypt(ciphertext, key), expected);
    }

    #[test]
    fn test_aes128_encrypt() {
        let key = &[
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let plaintext = &[
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
        ];
        let expected = &[
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66,
            0xef, 0x97, 0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf
        ];
        assert_eq!(aes128_encrypt(plaintext, key, AesMode::ECB), expected);
    }
}
