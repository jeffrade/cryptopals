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
