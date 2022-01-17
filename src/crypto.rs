use crate::file::{read_file, write_file};
use aes_gcm_siv::aead::{Aead, NewAead};
use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce};
use anyhow::{anyhow, Result};
use pbkdf2::{password_hash::PasswordHasher, Pbkdf2};
use rand::{distributions::Alphanumeric, Rng};

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const SALT_LEN: usize = 12;

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
    fn parse(salt: String, password: &String) -> Result<Pbkdf2Key> {
        let hash = Pbkdf2Key::hash_password(password.as_bytes(), &salt)?;
        Ok(Pbkdf2Key {
            salt: salt,
            hash: hash,
        })
    }

    fn new(password: &String) -> Result<Pbkdf2Key> {
        Pbkdf2Key::parse(Pbkdf2Key::new_salt(), password)
    }

    fn new_salt() -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(SALT_LEN)
            .map(char::from)
            .collect()
    }

    fn hash_password(password: &[u8], salt: &String) -> Result<Vec<u8>> {
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

        let key_vec = Crypto::serialize_key(
            pbkdf2_key.salt.as_bytes(),
            &file_aes_key.nonce,
            &file_aes_key_ciphertext,
        );

        write_file(&self.key_path, key_vec, true)?;
        Ok(println!("Created key at {}.", self.key_path.display()))
    }

    pub fn change_password(&mut self, new_password: String) -> Result<()> {
        let file_aes_key = self.parse_file_aes_key()?;
        self.password = new_password;
        let pbkdf2_key = Pbkdf2Key::new(&self.password)?;
        let pw_aes_key = AesKey::parse(&file_aes_key.nonce, pbkdf2_key.hash);

        let file_aes_key_ciphertext = Crypto::encrypt(&file_aes_key.key, &pw_aes_key)?;

        let key_vec = Crypto::serialize_key(
            pbkdf2_key.salt.as_bytes(),
            &file_aes_key.nonce,
            &file_aes_key_ciphertext,
        );

        write_file(&self.key_path, key_vec, false)?;
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
        let cipher_text = Crypto::encrypt(&content, &aes_key)?;
        write_file(&output, cipher_text, true)?;
        Ok(println!("File encrypted at {}.", output.display()))
    }

    pub fn decrypt_file(
        &self,
        input: std::path::PathBuf,
        output: std::path::PathBuf,
    ) -> Result<()> {
        let aes_key = self.parse_file_aes_key()?;
        let content = read_file(&input)?;
        let plain_text = Crypto::decrypt(&content, &aes_key)?;
        write_file(&output, plain_text, true)?;
        Ok(println!("File decrypted at {}.", output.display()))
    }

    fn parse_pbkdf2_key(&self) -> Result<Pbkdf2Key> {
        let key_vec = read_file(&self.key_path)?;
        let pbkdf2_salt = String::from_utf8(key_vec[0..SALT_LEN].to_vec())?;
        Pbkdf2Key::parse(pbkdf2_salt, &self.password)
    }

    fn parse_pw_aes_key(&self, nonce: &[u8]) -> Result<AesKey> {
        let pbkdf2_key = self.parse_pbkdf2_key()?;
        Ok(AesKey::parse(nonce, pbkdf2_key.hash))
    }

    fn parse_file_aes_key(&self) -> Result<AesKey> {
        let key_vec = read_file(&self.key_path)?;
        let nonce = &key_vec[SALT_LEN + 1..SALT_LEN + NONCE_LEN + 1];
        let aes_key_ciphertext = key_vec[SALT_LEN + NONCE_LEN + 2..key_vec.len() - 1].to_vec();

        let pw_aes_key = self.parse_pw_aes_key(nonce)?;
        let aes_key = match Crypto::decrypt(&aes_key_ciphertext, &pw_aes_key) {
            Ok(key) => key,
            Err(_) => return Err(anyhow!("Key authentication failure.")),
        };
        println!("Key authenticated.");
        Ok(AesKey::parse(nonce, aes_key))
    }

    fn serialize_key(
        pbkdf2_salt: &[u8],
        aes_nonce: &[u8],
        file_aes_key_ciphertext: &[u8],
    ) -> Vec<u8> {
        let mut key_vec = Vec::new();
        key_vec.extend(pbkdf2_salt);
        key_vec.push(b'\n');
        key_vec.extend(aes_nonce);
        key_vec.push(b'\n');
        key_vec.extend(file_aes_key_ciphertext);
        key_vec.push(b'\n');
        key_vec
    }

    fn encrypt(input: &Vec<u8>, aes_key: &AesKey) -> Result<Vec<u8>> {
        match aes_key.cipher.encrypt(&aes_key.nonce, input.as_ref()) {
            Ok(plain_text) => Ok(plain_text),
            Err(_) => Err(anyhow!("Encryption failure!")),
        }
    }

    fn decrypt(input: &Vec<u8>, aes_key: &AesKey) -> Result<Vec<u8>> {
        match aes_key.cipher.decrypt(&aes_key.nonce, input.as_ref()) {
            Ok(plain_text) => Ok(plain_text),
            Err(_) => Err(anyhow!("Decryption failure!")),
        }
    }
}
