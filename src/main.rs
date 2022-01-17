use anyhow::Result;
mod command_parser;
mod crypto;
mod file;


fn main() -> Result<()> {
    
    command_parser::parse()
}
