use crate::file::{read_file, write_file};
use aes_gcm_siv::aead::{Aead, NewAead};
use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce};
use anyhow::{anyhow, Result};
use base64::{decode, encode};
use pbkdf2::{password_hash::PasswordHasher, Pbkdf2};
use rand::{distributions::Alphanumeric, Rng};
use std::str;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const SALT_LEN: usize = 12;

const PBKDF2_SALT_START_TAG: &str = "-----BEGIN PBKDF2 SALT-----";
const PBKDF2_SALT_END_TAG: &str = "-----END PBKDF2 SALT-----";
const AES_NONE_START_TAG: &str = "-----BEGIN AES NONCE-----";
const AES_NONE_END_TAG: &str = "-----END AES NONCE-----";
const AES_KEY_START_TAG: &str = "-----BEGIN AES KEY-----";
const AES_KEY_END_TAG: &str = "-----END AES KEY-----";

const BASE64_LINE_SIZE: usize = 64;

struct AesKey {
    nonce: Nonce,
    key: Vec<u8>,
    cipher: Aes256GcmSiv,
}

impl AesKey {
    fn parse(nonce: &[u8], key: Vec<u8>) -> AesKey {
        let nonce = Nonce::from_slice(nonce);
        let cipher = AesKey::generate_cipher(&key);
        AesKey {
            nonce: *nonce,
            key: key,
            cipher: cipher,
        }
    }

    fn new() -> AesKey {
        AesKey::parse(&AesKey::new_nonce(), AesKey::new_key())
    }

    fn new_nonce() -> [u8; NONCE_LEN] {
        let nonce: [u8; NONCE_LEN] = rand::random();
        nonce
    }

    fn new_key() -> Vec<u8> {
        let key: [u8; KEY_LEN] = rand::random();
        key.to_vec()
    }

    fn generate_cipher(key: &Vec<u8>) -> Aes256GcmSiv {
        let key = Key::from_slice(&key);
        Aes256GcmSiv::new(key)
    }
}

struct Pbkdf2Key {
    salt: String,
    hash: Vec<u8>,
}

impl Pbkdf2Key {
    fn parse(password: &str, salt: String) -> Result<Pbkdf2Key> {
        let hash = Pbkdf2Key::hash_password(password.as_bytes(), &salt)?;
        Ok(Pbkdf2Key {
            salt: salt,
            hash: hash,
        })
    }

    fn new(password: &str) -> Result<Pbkdf2Key> {
        Pbkdf2Key::parse(password, Pbkdf2Key::new_salt())
    }

    fn new_salt() -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(SALT_LEN)
            .map(char::from)
            .collect()
    }

    fn hash_password(password: &[u8], salt: &str) -> Result<Vec<u8>> {
        match Pbkdf2.hash_password(password, &salt) {
            Ok(hash) => Ok(hash.hash.unwrap().as_bytes()[0..KEY_LEN].to_vec()),
            Err(_) => Err(anyhow!("PBKDF2 hash error.")),
        }
    }
}

pub struct Crypto {
    pub password: String,
    pub key_path: std::path::PathBuf,
}

impl Crypto {
    pub fn create_key(&self) -> Result<()> {
        println!("Creating key...");
        let pbkdf2_key = Pbkdf2Key::new(&self.password)?;
        let file_aes_key = AesKey::new();
        let pw_aes_key = AesKey::parse(&file_aes_key.nonce, pbkdf2_key.hash);

        let file_aes_key_ciphertext = Crypto::encrypt(&file_aes_key.key, &pw_aes_key)?;

        let key_str = Crypto::serialize_key(
            pbkdf2_key.salt,
            &file_aes_key.nonce,
            &file_aes_key_ciphertext,
        );

        write_file(&self.key_path, key_str.into_bytes(), true)?;
        Ok(println!("Created key at {}.", self.key_path.display()))
    }

    pub fn change_password(&mut self, new_password: String) -> Result<()> {
        let file_aes_key = self.parse_file_aes_key()?;
        self.password = new_password;
        let pbkdf2_key = Pbkdf2Key::new(&self.password)?;
        let pw_aes_key = AesKey::parse(&file_aes_key.nonce, pbkdf2_key.hash);

        let file_aes_key_ciphertext = Crypto::encrypt(&file_aes_key.key, &pw_aes_key)?;

        let key_str = Crypto::serialize_key(
            pbkdf2_key.salt,
            &file_aes_key.nonce,
            &file_aes_key_ciphertext,
        );

        write_file(&self.key_path, key_str.into_bytes(), false)?;
        Ok(println!(
            "Changed the password of key at {}.",
            self.key_path.display()
        ))
    }

    pub fn encrypt_file(
        &self,
        input: std::path::PathBuf,
        output: std::path::PathBuf,
    ) -> Result<()> {
        let aes_key = self.parse_file_aes_key()?;
        let content = read_file(&input)?;
        let ciphertext = Crypto::split_base64(encode(Crypto::encrypt(&content, &aes_key)?));
        write_file(&output, ciphertext.into_bytes(), true)?;
        Ok(println!("File encrypted at {}.", output.display()))
    }

    pub fn decrypt_file(
        &self,
        input: std::path::PathBuf,
        output: std::path::PathBuf,
    ) -> Result<()> {
        let aes_key = self.parse_file_aes_key()?;
        let content = decode(Crypto::unsplit_base64(read_file(&input)?))?;
        let plaintext = Crypto::decrypt(&content, &aes_key)?;
        write_file(&output, plaintext, true)?;
        Ok(println!("File decrypted at {}.", output.display()))
    }

    fn parse_pbkdf2_key(&self) -> Result<Pbkdf2Key> {
        let key_vec = read_file(&self.key_path)?;
        let s = str::from_utf8(&key_vec)?;

        let start = match s.find(PBKDF2_SALT_START_TAG) {
            Some(index) => index + PBKDF2_SALT_START_TAG.chars().count() + 1,
            None => return Err(anyhow!("Key parsing failure.")),
        };
        let end = match s.find(PBKDF2_SALT_END_TAG) {
            Some(index) => index - 1,
            None => return Err(anyhow!("Key parsing failure.")),
        };

        let pbkdf2_salt = String::from_utf8(key_vec[start..end].to_vec())?;
        Pbkdf2Key::parse(&self.password, pbkdf2_salt)
    }

    fn parse_pw_aes_key(&self, nonce: &[u8]) -> Result<AesKey> {
        let pbkdf2_key = self.parse_pbkdf2_key()?;
        Ok(AesKey::parse(nonce, pbkdf2_key.hash))
    }

    fn parse_file_aes_key(&self) -> Result<AesKey> {
        let key_vec = read_file(&self.key_path)?;
        let s = str::from_utf8(&key_vec)?;

        let start = match s.find(AES_NONE_START_TAG) {
            Some(index) => index + AES_NONE_START_TAG.chars().count() + 1,
            None => return Err(anyhow!("Key parsing failure.")),
        };
        let end = match s.find(AES_NONE_END_TAG) {
            Some(index) => index - 1,
            None => return Err(anyhow!("Key parsing failure.")),
        };
        let nonce = &decode(&key_vec[start..end])?;

        let start = match s.find(AES_KEY_START_TAG) {
            Some(index) => index + AES_KEY_START_TAG.chars().count() + 1,
            None => return Err(anyhow!("Key parsing failure.")),
        };
        let end = match s.find(AES_KEY_END_TAG) {
            Some(index) => index - 1,
            None => return Err(anyhow!("Key parsing failure.")),
        };
        let aes_key_ciphertext = decode(&key_vec[start..end])?;

        let pw_aes_key = self.parse_pw_aes_key(nonce)?;
        let aes_key = match Crypto::decrypt(&aes_key_ciphertext, &pw_aes_key) {
            Ok(key) => key,
            Err(_) => return Err(anyhow!("Key authentication failure.")),
        };
        println!("Key authenticated.");
        Ok(AesKey::parse(nonce, aes_key))
    }

    fn serialize_key(
        pbkdf2_salt: String,
        aes_nonce: &[u8],
        file_aes_key_ciphertext: &[u8],
    ) -> String {
        format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            PBKDF2_SALT_START_TAG,
            pbkdf2_salt,
            PBKDF2_SALT_END_TAG,
            AES_NONE_START_TAG,
            encode(aes_nonce),
            AES_NONE_END_TAG,
            AES_KEY_START_TAG,
            encode(file_aes_key_ciphertext),
            AES_KEY_END_TAG,
        )
    }

    fn encrypt(input: &Vec<u8>, aes_key: &AesKey) -> Result<Vec<u8>> {
        match aes_key.cipher.encrypt(&aes_key.nonce, input.as_ref()) {
            Ok(plaintext) => Ok(plaintext),
            Err(_) => Err(anyhow!("Encryption failure!")),
        }
    }

    fn decrypt(input: &Vec<u8>, aes_key: &AesKey) -> Result<Vec<u8>> {
        match aes_key.cipher.decrypt(&aes_key.nonce, input.as_ref()) {
            Ok(plaintext) => Ok(plaintext),
            Err(_) => Err(anyhow!("Decryption failure!")),
        }
    }

    fn split_base64(mut ciphertext: String) -> String {
        let mut i = BASE64_LINE_SIZE;
        while i < ciphertext.chars().count() {
            ciphertext.insert(i, '\n');
            i += BASE64_LINE_SIZE + 1;
        }
        ciphertext.push('\n');
        ciphertext
    }

    fn unsplit_base64(mut ciphertext: Vec<u8>) -> Vec<u8> {
        let mut i = 0;
        while i < ciphertext.len() {
            if ciphertext[i] == b'\n' {
                ciphertext.remove(i);
                i -= 1;
            }
            i += 1;
        }
        ciphertext
    }
}
