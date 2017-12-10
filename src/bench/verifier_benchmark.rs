extern crate time;
extern crate base64;

use app::verifier::Verifier;
use app::logger::Logger;
use bench::util::*;
use cfg::config::Config;
use cfg::settings::KeyEntropy;
use self::time::PreciseTime;
use std::fs;
use std::path::Path;
use util::hash::{sha256_trunc_128, sha512, HashChain};
use util::key_derivation::derive_key_pair;
use util::misc::pad;

pub fn run() -> Vec<(String, i64, i64)> {
    let cfgs_short = Cfgs::new(1);
    let cfgs_long = Cfgs::new(20);
    let num_lines: Vec<usize> = vec![1, 10, 100, 1000];
    let mut results: Vec<(String, i64, i64)> = vec![];
    
    for i in 0..cfgs_short.v.len() {
        num_lines.iter()
            .for_each(|n| {
                results.push(verify_n_lines(*n, cfgs_short.v[i].1, cfgs_short.v[i].0));
                results.push(verify_n_lines(*n, cfgs_long.v[i].1, cfgs_long.v[i].0));
            });
    }
    
    results
}

fn verify_n_lines(n: usize, cfg: Config, cfg_key: &str) -> (String, i64, i64) {
    let path = format!("verify_{}_lines_block_len_{}_{}", n, cfg.cipher_block_len, cfg_key);
    let secret_root = init(&path, cfg);
    let mut logger = Logger::new(cfg, &path, &secret_root.0, &secret_root.1);
    let message = String::from("test");
    let mut measurements = [0; NUM_TESTS];
    
    for _ in 0..n { logger.log(&message).unwrap() };
    
    let keys = get_signature_keys(&secret_root.1, n, cfg.key_entropy);
    let keys_borrowed: Vec<&Vec<u8>> = keys.iter().map(|key| key).collect();
    let first_decryption_key = derive_key_pair(&secret_root.1, cfg.key_entropy).encryption;
    
    for i in 0..NUM_TESTS {
        let verifier = Verifier::new(&path);
        let start = PreciseTime::now();
        verifier.verify(&secret_root.0, &keys_borrowed, &first_decryption_key).unwrap();
        measurements[i] = start.to(PreciseTime::now()).num_nanoseconds().unwrap();
    }
    fs::remove_file(&path).expect("Could not delete generated benchmark file.");
    
    let mean = mean(&measurements);
    
    (String::from(path), mean, std_dev(&measurements, mean))
}

fn init(path: &str, cfg: Config) -> (String, [u8; 64]) {
    if Path::new(path).exists() {
        fs::remove_file(&path).expect("Failed to delete leftover benchmark file.");
    }
    let mut secret = pad(&base64::encode(&sha256_trunc_128(path.as_bytes())), cfg.max_msg_len());
    let root = sha512(path.as_bytes());
    
    if secret.len() > cfg.max_msg_len() { secret = secret[0..cfg.max_msg_len()].to_string() }
    
    (secret, root)
}

fn get_signature_keys(root: &[u8; 64], amount: usize, entropy: KeyEntropy) -> Vec<Vec<u8>> {
    let mut chain = HashChain::new(root);
    let mut keys: Vec<Vec<u8>> = vec![];
    
    for _ in 0..amount {
        keys.push(derive_key_pair(&chain.get_node(), entropy).signature);
        chain.evolve();
    }
    
    keys
}
