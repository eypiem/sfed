use crate::crypto::Crypto;
use anyhow::Result;
use clap::{arg, App, AppSettings};
use rpassword;
use std::path::PathBuf;


const PW_MIN_LEN: usize = 8;

pub fn parse() -> Result<()> {
    let matches = App::new("sfed")
        .about("Simple file encryptor and decryptor")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .setting(AppSettings::AllowExternalSubcommands)
        .setting(AppSettings::AllowInvalidUtf8ForExternalSubcommands)
        .subcommand(
            App::new("new-key")
                .about("Creates a new key.")
                .arg(arg!(<KEY_PATH> "Path to the new key"))
                .setting(AppSettings::ArgRequiredElseHelp),
        )
        .subcommand(
            App::new("change-password")
                .about("Changes the password of a key.")
                .arg(arg!(<KEY_PATH> "Path to the key"))
                .setting(AppSettings::ArgRequiredElseHelp),
        )
        .subcommand(
            App::new("encrypt")
                .about("Encrypts a file.")
                .arg(arg!(<PLAIN_TEXT> "Path to plaintext file"))
                .arg(arg!(<CIPHER_TEXT> "Path to ciphertext file"))
                .arg(arg!(<KEY_PATH> "Path to the key"))
                .setting(AppSettings::ArgRequiredElseHelp),
        )
        .subcommand(
            App::new("decrypt")
                .about("Decrypts a file.")
                .arg(arg!(<CIPHER_TEXT> "Path to ciphertext file"))
                .arg(arg!(<PLAIN_TEXT> "Path to plaintext file"))
                .arg(arg!(<KEY_PATH> "Path to the key"))
                .setting(AppSettings::ArgRequiredElseHelp),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("new-key", sub_matches)) => new_key(sub_matches),
        Some(("change-password", sub_matches)) => change_key_password(sub_matches),
        Some(("encrypt", sub_matches)) => encrypt(sub_matches),
        Some(("decrypt", sub_matches)) => decrypt(sub_matches),
        _ => panic!("Undefined command."),
    }
}

fn get_password(message: Option<&str>) -> Result<String> {
    let msg: &str = match message {
        Some(msg) => msg,
        None => "Enter password: ",
    };

    loop {
        match rpassword::read_password_from_tty(Some(msg)) {
            Ok(pw) => {
                if pw.chars().count() >= PW_MIN_LEN {
                    return Ok(pw);
                }
                println!("Password must be at least {} characters.", PW_MIN_LEN);
            }
            Err(_) => println!("Error reading password."),
        }
    }
}

fn new_key(sub_matches: &clap::ArgMatches) -> Result<()> {
    let key_path = PathBuf::from(sub_matches.value_of("KEY_PATH").unwrap_or_default());
    let c = Crypto {
        password: get_password(None)?,
        key_path: key_path,
    };
    c.create_key()
}

fn change_key_password(sub_matches: &clap::ArgMatches) -> Result<()> {
    let key_path = PathBuf::from(sub_matches.value_of("KEY_PATH").unwrap_or_default());
    let old_pw = get_password(Some("Enter old password: "))?;
    let new_pw_1 = get_password(Some("Enter new password: "))?;
    let new_pw_2 = get_password(Some("Repeat new password: "))?;

    if new_pw_1 != new_pw_2 {
        panic!("Passwords do not match.");
    }

    let mut c = Crypto {
        password: old_pw,
        key_path: key_path,
    };
    c.change_password(new_pw_1)
}

fn encrypt(sub_matches: &clap::ArgMatches) -> Result<()> {
    let key_path = PathBuf::from(sub_matches.value_of("KEY_PATH").unwrap_or_default());
    let input = PathBuf::from(sub_matches.value_of("PLAIN_TEXT").unwrap_or_default());
    let output = PathBuf::from(sub_matches.value_of("CIPHER_TEXT").unwrap_or_default());

    if !key_path.exists() {
        panic!(r#"Key does not exist. Use the "generate" command to create a key."#);
    } else {
        let c = Crypto {
            password: get_password(None)?,
            key_path: key_path,
        };
        c.encrypt_file(input, output)
    }
}

fn decrypt(sub_matches: &clap::ArgMatches) -> Result<()> {
    let key_path = PathBuf::from(sub_matches.value_of("KEY_PATH").unwrap_or_default());
    let input = PathBuf::from(sub_matches.value_of("CIPHER_TEXT").unwrap_or_default());
    let output = PathBuf::from(sub_matches.value_of("PLAIN_TEXT").unwrap_or_default());

    let c = Crypto {
        password: get_password(None)?,
        key_path: key_path,
    };
    c.decrypt_file(input, output)
}
