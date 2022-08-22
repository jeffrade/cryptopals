use crate::crypto::util::*;

pub fn start() {
    println!("Starting Set 1, Challenge 9...");

    let mut plaintext_blocks: Vec<&[u8]> = vec![
        "A TWENTY BYTE BLOCK!".as_bytes(),
        "YELLOW SUBMARINE".as_bytes(),
    ];
    let expected_blocks: Vec<&[u8]> = vec![
        "A TWENTY BYTE BLOCK!".as_bytes(),
        "YELLOW SUBMARINE\u{4}\u{4}\u{4}\u{4}".as_bytes(),
    ];

    let last_block = plaintext_blocks.pop().unwrap();
    let padded_block = add_pkcs7_padding(last_block, 20);

    plaintext_blocks.push(&padded_block);
    assert_eq!(plaintext_blocks, expected_blocks,);

    println!("Done!")
}
