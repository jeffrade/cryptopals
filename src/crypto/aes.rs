#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(clippy::identity_op)]
/* The ecb_128_[encrypt|decrypt] function implementations are taken from https://github.com/kokke/tiny-AES-c */

// The number of columns comprising a state in AES. This is a constant in AES. Value=4
const Nb: usize = 4;

// The round constant word array, Rcon[i], contains the values given by
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
const Rcon: [u8; 11] = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
];

const sbox: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const rsbox: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

pub fn ecb_128_encrypt(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    // state - array holding the intermediate results during decryption.
    let mut state: [[u8; 4]; 4] = init_state(plaintext);

    let Nk: usize = 4; // The number of 32 bit words in a 128 bit key.
    let Nr: usize = 10; // The number of rounds in AES Cipher.

    state = Cipher(key, state, Nk, Nr);

    flatten_state(state)
}

pub fn ecb_128_decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    // state - array holding the intermediate results during decryption.
    let mut state: [[u8; 4]; 4] = init_state(ciphertext);

    let Nk: usize = 4; // The number of 32 bit words in a 128 bit key.
    let Nr: usize = 10; // The number of rounds in AES Cipher.
    state = InvCipher(key, state, Nk, Nr);

    flatten_state(state)
}

pub fn cbc_128_encrypt(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    vec![] // TODO
}

pub fn cbc_128_decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    vec![] // TODO
}

fn Cipher(key: &[u8], mut state: [[u8; 4]; 4], Nk: usize, Nr: usize) -> [[u8; 4]; 4] {
    let RoundKey = KeyExpansion(key, Nk, Nr);
    let mut round: usize = 0;

    // Add the First round key to the state before starting the rounds.
    state = AddRoundKey(round, state, &RoundKey);
    round += 1;

    // There will be Nr rounds.
    // The first Nr-1 rounds are identical.
    // These Nr rounds are executed in the loop below.
    // Last one without MixColumns()
    loop {
        state = SubBytes(state);
        state = ShiftRows(state);
        if round == Nr {
            break;
        }
        state = MixColumns(state);
        state = AddRoundKey(round, state, &RoundKey);
        round += 1;
    }

    // Add round key to last round
    AddRoundKey(Nr, state, &RoundKey)
}

fn InvCipher(key: &[u8], mut state: [[u8; 4]; 4], Nk: usize, Nr: usize) -> [[u8; 4]; 4] {
    let RoundKey = KeyExpansion(key, Nk, Nr);
    let mut round: usize = Nr;

    // Add the First round key to the state before starting the rounds.
    state = AddRoundKey(round, state, &RoundKey);
    round -= 1;

    // There will be Nr rounds.
    // The first Nr-1 rounds are identical.
    // These Nr rounds are executed in the loop below.
    // Last one without InvMixColumn()
    loop {
        state = InvShiftRows(state);
        state = InvSubBytes(state);
        state = AddRoundKey(round, state, &RoundKey);
        if round == 0 {
            break;
        }
        state = InvMixColumns(state);
        round -= 1;
    }
    state
}

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.
fn KeyExpansion(Key: &[u8], Nk: usize, Nr: usize) -> Vec<u8> {
    // https://github.com/kokke/tiny-AES-c/blob/12e7744b4919e9d55de75b7ab566326a1c8e7a67/aes.h#L33-L42
    let mut key_exp_size = 176;
    if Nk == 6 {
        key_exp_size = 208;
    } else if Nk == 8 {
        key_exp_size = 240;
    }
    let mut RoundKey: Vec<u8> = vec![0; key_exp_size];
    let mut tempa: [u8; 4] = [0; 4]; // Used for the column/row operations

    // The first round key is the key itself.
    for i in 0..Nk {
        RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
        RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
        RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
        RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
    }

    // All other round keys are found from the previous round keys.
    let mut i = Nk;
    while i < Nb * (Nr + 1) {
        let mut k = (i - 1) * 4;
        tempa[0] = RoundKey[k + 0];
        tempa[1] = RoundKey[k + 1];
        tempa[2] = RoundKey[k + 2];
        tempa[3] = RoundKey[k + 3];

        if i % Nk == 0 {
            // This function shifts the 4 bytes in a word to the left once.
            // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

            // Function RotWord()
            let u8tmp: u8 = tempa[0];
            tempa[0] = tempa[1];
            tempa[1] = tempa[2];
            tempa[2] = tempa[3];
            tempa[3] = u8tmp;

            // SubWord() is a function that takes a four-byte input word and
            // applies the S-box to each of the four bytes to produce an output word.

            // Function Subword()
            tempa[0] = getSBoxValue(tempa[0] as usize);
            tempa[1] = getSBoxValue(tempa[1] as usize);
            tempa[2] = getSBoxValue(tempa[2] as usize);
            tempa[3] = getSBoxValue(tempa[3] as usize);

            tempa[0] ^= Rcon[i / Nk];
        }

        if Nk > 4 {
            // TODO https://github.com/kokke/tiny-AES-c/blob/master/aes.c#L200_L209
            panic!("Need to implement for AES 192 and 256");
        }

        let j = i * 4;
        k = (i - Nk) * 4;
        RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
        RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
        RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
        RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];

        i += 1;
    }
    RoundKey
}

fn getSBoxValue(num: usize) -> u8 {
    sbox[num]
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
fn AddRoundKey(round: usize, mut state: [[u8; 4]; 4], key: &[u8]) -> [[u8; 4]; 4] {
    for i in [0, 1, 2, 3] {
        for j in [0, 1, 2, 3] {
            state[i][j] ^= key[(round * Nb * 4) + (i * Nb) + j];
        }
    }
    state
}

fn InvShiftRows(mut state: [[u8; 4]; 4]) -> [[u8; 4]; 4] {
    // Rotate first row 1 columns to right
    let mut temp: u8 = state[3][1];
    state[3][1] = state[2][1];
    state[2][1] = state[1][1];
    state[1][1] = state[0][1];
    state[0][1] = temp;

    // Rotate second row 2 columns to right
    temp = state[0][2];
    state[0][2] = state[2][2];
    state[2][2] = temp;

    temp = state[1][2];
    state[1][2] = state[3][2];
    state[3][2] = temp;

    // Rotate third row 3 columns to right
    temp = state[0][3];
    state[0][3] = state[1][3];
    state[1][3] = state[2][3];
    state[2][3] = state[3][3];
    state[3][3] = temp;
    state
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
fn ShiftRows(mut state: [[u8; 4]; 4]) -> [[u8; 4]; 4] {
    // Rotate first row 1 columns to left
    let mut temp: u8 = state[0][1];
    state[0][1] = state[1][1];
    state[1][1] = state[2][1];
    state[2][1] = state[3][1];
    state[3][1] = temp;

    // Rotate second row 2 columns to left
    temp = state[0][2];
    state[0][2] = state[2][2];
    state[2][2] = temp;

    temp = state[1][2];
    state[1][2] = state[3][2];
    state[3][2] = temp;

    // Rotate third row 3 columns to left
    temp = state[0][3];
    state[0][3] = state[3][3];
    state[3][3] = state[2][3];
    state[2][3] = state[1][3];
    state[1][3] = temp;
    state
}

fn InvSubBytes(mut state: [[u8; 4]; 4]) -> [[u8; 4]; 4] {
    for i in [0, 1, 2, 3] {
        for j in [0, 1, 2, 3] {
            state[j][i] = getSBoxInvert(state[j][i] as usize);
        }
    }
    state
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
fn SubBytes(mut state: [[u8; 4]; 4]) -> [[u8; 4]; 4] {
    for i in [0, 1, 2, 3] {
        for j in [0, 1, 2, 3] {
            state[j][i] = getSBoxValue(state[j][i] as usize);
        }
    }
    state
}

fn getSBoxInvert(num: usize) -> u8 {
    rsbox[num]
}

fn InvMixColumns(mut state: [[u8; 4]; 4]) -> [[u8; 4]; 4] {
    for i in [0, 1, 2, 3] {
        let a: u8 = state[i][0];
        let b: u8 = state[i][1];
        let c: u8 = state[i][2];
        let d: u8 = state[i][3];

        state[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
        state[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
        state[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
        state[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
    }

    state
}

// MixColumns function mixes the columns of the state matrix
fn MixColumns(mut state: [[u8; 4]; 4]) -> [[u8; 4]; 4] {
    for i in [0, 1, 2, 3] {
        let t = state[i][0];
        let Tmp = state[i][0] ^ state[i][1] ^ state[i][2] ^ state[i][3];
        let mut Tm = state[i][0] ^ state[i][1];
        Tm = xtime(Tm);
        state[i][0] ^= Tm ^ Tmp;
        Tm = state[i][1] ^ state[i][2];
        Tm = xtime(Tm);
        state[i][1] ^= Tm ^ Tmp;
        Tm = state[i][2] ^ state[i][3];
        Tm = xtime(Tm);
        state[i][2] ^= Tm ^ Tmp;
        Tm = state[i][3] ^ t;
        Tm = xtime(Tm);
        state[i][3] ^= Tm ^ Tmp;
    }
    state
}

fn Multiply(x: u8, y: u8) -> u8 {
    ((y & 1) * x)
        ^ ((y >> 1 & 1) * xtime(x))
        ^ ((y >> 2 & 1) * xtime(xtime(x)))
        ^ ((y >> 3 & 1) * xtime(xtime(xtime(x))))
        ^ ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x)))))
}

fn xtime(x: u8) -> u8 {
    (x << 1) ^ (((x >> 7) & 1) * 0x1b)
}

fn init_state(text: &[u8]) -> [[u8; 4]; 4] {
    let mut state: [[u8; 4]; 4] = [[0; 4]; 4];
    for i in [0, 1, 2, 3] {
        for j in [0, 1, 2, 3] {
            state[i][j] = text[i * 4 + j];
        }
    }
    state
}

fn flatten_state(state: [[u8; 4]; 4]) -> Vec<u8> {
    let mut text: Vec<u8> = vec![];
    for i in [0, 1, 2, 3] {
        for j in [0, 1, 2, 3] {
            text.push(state[i][j]);
        }
    }
    text
}
