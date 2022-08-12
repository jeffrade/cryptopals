use crate::util::*;

pub fn start() {
    println!("Starting Set 1, Challenge 8...");

    let mut line_num = 1;
    for line in get_file_lines("challenge-data/8.txt") {
        let ciphertext_hex = line.unwrap();
        // Let's assume that we will find matching 16 byte blocks.
        for i in [16] {
            if find_repeating_blocks(&ciphertext_hex, i as usize) {
                println!(
                    "RING RING, RING RING, got a hit: line {}, size {}",
                    line_num, i
                );
            }
        }
        line_num += 1;
    }

    println!("Done!")
}

fn find_repeating_blocks(line: &str, size: usize) -> bool {
    let mut found: bool = false;
    let str_len = line.len();
    let mut index = 0;
    while (index + size) < str_len {
        let start = index;
        let end = index + size;
        let temp = &line[start..end];
        let remaining = line.to_string().split_off(end - 1);
        if remaining.contains(temp) {
            println!("Found a match! {:?}", temp);
            found = true;
        }
        index += size;
    }
    found
}
