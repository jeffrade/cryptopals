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

_One of the 60-character strings in [this file](https://cryptopals.com/static/challenge-data/4.txt) has been encrypted by single-character XOR._

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
