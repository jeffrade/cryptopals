pub fn add_pkcs7_padding(plaintext: &[u8], blocksize: usize) -> Vec<u8> {
    let padding_amt = blocksize - plaintext.len();
    let mut new_plaintext = plaintext.to_vec();
    let mut i: usize = 0;
    while i < padding_amt {
        new_plaintext.push(padding_amt as u8);
        i += 1;
    }
    new_plaintext
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_pkcs7_padding() {
        assert_eq!(
            add_pkcs7_padding("YELLOW".as_bytes(), 8),
            "YELLOW\u{2}\u{2}".as_bytes()
        );
    }
}
