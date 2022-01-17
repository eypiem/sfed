# Simple File Encryptor and Decryptor

This Rust-written CLI tool allows the user to encrypt and decrypt files using a password. 
An [AES-GCM-SIV](https://en.wikipedia.org/wiki/AES-GCM-SIV) key is derived from the user's password via the [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) algorithm, this key is used to encrypt another AES key which will be stored as a file. This way, the user can change their password without having to decrypt all the encrypted files first.

## Usage

### Create a new key:
```bash
sfed new-key <KEY_PATH>
```

### Change key password:
```bash
sfed change-password <KEY_PATH>
```

### Encrypt a file:
```bash
sfed encrypt <PLAIN_TEXT> <CIPHER_TEXT> <KEY_PATH>
```

### Decrypt a file:
```bash
sfed decrypt <PLAIN_TEXT> <CIPHER_TEXT> <KEY_PATH>
```


## Warning

 This tool is not intended for practical use.
