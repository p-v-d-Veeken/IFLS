#[macro_use]
extern crate clap;

mod app;
mod bench;
mod cli;
mod cfg;
mod log;
mod util;

use clap::App;
use cli::exec::{encrypt_file, decrypt_file, verify_file, generate_keys, benchmark};

fn main() {
    let yml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yml).get_matches();
    let encrypt_matches = matches.subcommand_matches("encrypt");
    let decrypt_matches = matches.subcommand_matches("decrypt");
    let verify_matches = matches.subcommand_matches("verify");
    let keygen_matches = matches.subcommand_matches("keygen");
    let benchmark_matches = matches.subcommand_matches("benchmark");
    let res =
        if encrypt_matches.is_some() {
            encrypt_file(encrypt_matches.unwrap())
        } else if decrypt_matches.is_some() {
            decrypt_file(decrypt_matches.unwrap())
        } else if keygen_matches.is_some() {
            generate_keys(keygen_matches.unwrap())
        } else if verify_matches.is_some() {
            verify_file(verify_matches.unwrap())
        } else if benchmark_matches.is_some() {
            Ok(benchmark())
        } else { Err(String::from("Invalid sub-command.")) };
    
    match res {
        Ok(_) => println!("Done!"),
        Err(ref e) => println!("{}", e)
    }
}
