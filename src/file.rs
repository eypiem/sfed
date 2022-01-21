use anyhow::{anyhow, Context, Result};
use std::fs;
use std::io::{self, Write};

pub fn read_file(file_path: &std::path::PathBuf) -> Result<Vec<u8>> {
    std::fs::read(file_path)
        .with_context(|| format!("could not read file `{}`", file_path.display()))
}

pub fn write_file(file_path: &std::path::PathBuf, content: Vec<u8>, safe: bool) -> Result<()> {
    if safe {
        if !check_overwrite(file_path) {
            return Err(anyhow!("Writing to output file canceled."));
        }
    }
    match file_path.parent() {
        Some(parent) => fs::create_dir_all(parent)
            .with_context(|| format!("Could not create directory `{}`", parent.display()))?,
        None => (),
    }
    fs::write(file_path, content)
        .with_context(|| format!("Could not write to file `{}`", file_path.display()))
}

fn check_overwrite(file_path: &std::path::PathBuf) -> bool {
    if file_path.exists() {
        print!(
            "A file exists at {}. Do you want to overwrite it? [y/N]: ",
            file_path.display()
        );
        let _ = io::stdout().flush();
        let mut answer: String = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .expect("Invalid input.");

        return answer == "y\n" || answer == "Y\n" || answer == "y\r\n" || answer == "Y\r\n";
    }
    true
}
