
# Simple File Encryptor and Decryptor

This Rust-written CLI tool allows the user to encrypt and decrypt files with a passphrase. 
An [AES-GCM-SIV](https://en.wikipedia.org/wiki/AES-GCM-SIV) key is derived from the user's passphrase using the [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) algorithm. 
The key's parameters are stored in a file for future encryption and decryption.

## Usage

```bash
cargo run [-e, -d] <PASSWORD> <KEY_PATH> <INPUT> <OUTPUT>
```

Use `-e` for encryption and `-d` for decryption. A new key will be created and used for encryption if no file exists at `KEY_PATH`.

## Warning

 This tool is not intended for practical use.
