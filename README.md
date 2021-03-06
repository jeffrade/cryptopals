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
