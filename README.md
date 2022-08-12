# The [cryptopals.com](https://cryptopals.com) Crypto Challenges

Nice introductory can be found [here](https://blog.pinboard.in/2013/04/the_matasano_crypto_challenges/).

Unless specified, I've solved these using [Rust](https://www.rust-lang.org/).

## Set 1

### Challenge 1: Convert hex to base64

_The string:_
```
49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
```
_Should produce:_
```
SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
```

_So go ahead and make that happen. You'll need to use this code for the rest of the exercises._

_Cryptopals Rule: Always operate on raw bytes, never on encoded strings. Only use hex and base64 for pretty-printing._

### Challenge 2: Fixed XOR

_Write a function that takes two equal-length buffers and produces their XOR combination._

_If your function works properly, then when you feed it the string:_
```
1c0111001f010100061a024b53535009181c
```

_... after hex decoding, and when XOR'd against:_
```
686974207468652062756c6c277320657965
```

_... should produce:_
```
746865206b696420646f6e277420706c6179
```

### Challenge 3: Single-byte XOR cipher

_The hex encoded string:_
```
1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
```

_... has been XOR'd against a single character. Find the key, decrypt the message._

_You can do this by hand. But don't: write code to do it for you._

_How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score._

### Challenge 4: Detect single-character XOR

_One of the 60-character strings in [this file](https://raw.githubusercontent.com/jeffrade/cryptopals/master/challenge-data/4.txt) has been encrypted by single-character XOR._

_Find it._

_(Your code from #3 should help.)_

### Challenge 5: Implement repeating-key XOR

_Here is the opening stanza of an important work of the English language:_
```
Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal
```

_Encrypt it, under the key "ICE", using repeating-key XOR._

_In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on._

_It should come out to:_
```
0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
```

_Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this._

### Challenge 6: Break repeating-key XOR

_There's a file [here](https://raw.githubusercontent.com/jeffrade/cryptopals/master/challenge-data/6.txt). It's been base64'd after being encrypted with repeating-key XOR._

_Decrypt it._

_Here's how:_

1. _Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40._
2. _Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:_
```
this is a test
```
 _and_
```
wokka wokka!!!
```
 _is 37. Make sure your code agrees before you proceed._

3. _For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE._
4. _The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances._
5. _Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length_.
6. _Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on._
7. _Solve each block as if it was single-character XOR. You already have code to do this._
8. _For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key._

### Challenge 7: AES in ECB mode

_The Base64-encoded content [in this file](https://raw.githubusercontent.com/jeffrade/cryptopals/master/challenge-data/7.txt) has been encrypted via AES-128 in ECB mode under the key_
```
"YELLOW SUBMARINE".
```
_(case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too)._

_Decrypt it. You know the key, after all._

_Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher._

### Challenge 8: Detect AES in ECB mode

_[In this file](https://raw.githubusercontent.com/jeffrade/cryptopals/master/challenge-data/8.txt) are a bunch of hex-encoded ciphertexts._

_One of them has been encrypted with ECB._

_Detect it._

_Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext._
