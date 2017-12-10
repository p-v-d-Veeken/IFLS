extern crate base64;
extern crate time;

use app::logger::Logger;
use bench::util::*;
use cfg::config::Config;
use cfg::settings::KeyEntropy;
use log::log_entry::LogEntry;
use self::time::PreciseTime;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use util::crypt::encrypt;
use util::hash::{sha256_trunc_128, sha512, HashChain, hmac};
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
                results.push(log_n_lines(*n, cfgs_short.v[i].1, cfgs_short.v[i].0));
                results.push(log_n_lines(*n, cfgs_long.v[i].1, cfgs_long.v[i].0));
                results.push(log_n_lines_no_io(*n, cfgs_short.v[i].1, cfgs_short.v[i].0));
                results.push(log_n_lines_no_io(*n, cfgs_long.v[i].1, cfgs_long.v[i].0));
                
                if i == 0 {
                    results.push(log_n_lines_only_io(*n, cfgs_short.v[0].1));
                    results.push(log_n_lines_only_io(*n, cfgs_long.v[0].1));
                    results.push(do_n_hashchain_updates(*n));
                    results.push(encrypt_n_messages(*n, cfgs_short.v[0].1));
                    results.push(encrypt_n_messages(*n, cfgs_long.v[0].1));
                }
                if i == 0 || i == 4 {
                    results.push(calculate_n_signatures(*n, cfgs_short.v[i].1));
                    results.push(calculate_n_signatures(*n, cfgs_long.v[i].1));
                }
                if i < 3 {
                    results.push(derive_n_keys(*n, cfgs_short.v[i].1.key_entropy))
                }
            });
    };
    results.sort_by(|res_a, res_b| *(&res_a.1.cmp(&res_b.1)));
    
    results
}

fn log_n_lines(n: usize, cfg: Config, cfg_key: &str) -> (String, i64, i64) {
    let path = format!("log_{}_lines_block_len_{}_{}", n, cfg.cipher_block_len, cfg_key);
    let secret_root = init(&path, cfg);
    let mut logger = Logger::new(cfg, &path, &secret_root.0, &secret_root.1);
    let message = String::from("test");
    let mut measurements = [0; NUM_TESTS];
    
    for i in 0..NUM_TESTS {
        let start = PreciseTime::now();
        for _ in 0..n { logger.log(&message).unwrap() };
        measurements[i] = start.to(PreciseTime::now()).num_nanoseconds().unwrap();
    }
    fs::remove_file(&path).expect("Could not delete generated benchmark file.");
    
    let mean = mean(&measurements);
    
    (String::from(path), mean, std_dev(&measurements, mean))
}

fn log_n_lines_no_io(n: usize, cfg: Config, cfg_key: &str) -> (String, i64, i64) {
    let path = format!("log_{}_lines_no_io_block_len_{}_{}", n, cfg.cipher_block_len, cfg_key);
    let secret_root = init(&path, cfg);
    let msg = String::from("test");
    let mut chain = HashChain::new(&secret_root.1);
    let mut key_pair = derive_key_pair(&chain.get_node(), cfg.key_entropy);
    let mut entries = vec![
        LogEntry::new(&secret_root.0, &key_pair, cfg.hmac_alg).unwrap()
    ];
    let mut measurements = [0; NUM_TESTS];
    
    for i in 0..NUM_TESTS {
        let start = PreciseTime::now();
        
        for _ in 0..n {
            chain.evolve();
            key_pair = derive_key_pair(&chain.get_node(), cfg.key_entropy);
            
            let msg = pad(&msg, cfg.max_msg_len());
            let entry = LogEntry::new(&msg, &key_pair, cfg.hmac_alg).unwrap();
            let k = entries.len() - 1;
            
            entries[k].set_next_cipher(&entry.get_cipher(), &key_pair.signature, cfg.hmac_alg);
            entries.push(entry);
        }
        measurements[i] = start.to(PreciseTime::now()).num_nanoseconds().unwrap();
    }
    let mean = mean(&measurements);
    
    (String::from(path), mean, std_dev(&measurements, mean))
}

fn log_n_lines_only_io(n: usize, cfg: Config) -> (String, i64, i64) {
    let msg_len = cfg.max_msg_len();
    let path = format!("log_{}_lines_only_io_msg_len_{}", n, msg_len);
    
    if Path::new(&path).exists() {
        fs::remove_file(&path).expect("Failed to delete leftover benchmark file.");
    }
    let mut file = File::create(&path).expect("Could not create benchmark file.");
    let msg = String::from("test");
    let mut measurements = [0; NUM_TESTS];
    
    for i in 0..NUM_TESTS {
        let start = PreciseTime::now();
        
        for _ in 0..n {
            let padded_msg = pad(&msg, msg_len);
            
            file.write_all(padded_msg.as_bytes()).expect("Could not write to benchmark file.")
        }
        measurements[i] = start.to(PreciseTime::now()).num_nanoseconds().unwrap();
    }
    fs::remove_file(&path).expect("Could not delete generated benchmark file.");
    
    let mean = mean(&measurements);
    
    (path, mean, std_dev(&measurements, mean))
}

fn derive_n_keys(n: usize, key_entropy: KeyEntropy) -> (String, i64, i64) {
    let key = format!("derive_{}_keys_{:?}", n, key_entropy);
    let root = sha512(key.as_bytes());
    let mut chain = HashChain::new(&root);
    let mut measurements = [0; NUM_TESTS];
    
    for i in 0..NUM_TESTS {
        let start = PreciseTime::now();
        
        for j in 0..n {
            derive_key_pair(&chain.get_node(), key_entropy);
            
            if j != n - 1 { chain.evolve() }
        }
        measurements[i] = start.to(PreciseTime::now()).num_nanoseconds().unwrap();
    }
    let mean = mean(&measurements);
    
    (key, mean, std_dev(&measurements, mean))
}

fn calculate_n_signatures(n: usize, cfg: Config) -> (String, i64, i64) {
    let msg_len = cfg.max_msg_len();
    let hmac_alg = cfg.hmac_alg;
    let key = format!("calculate_{}_signatures_msg_len_{}_{:?}", n, msg_len, hmac_alg);
    let key_pair = derive_key_pair(&[0xff; 64], KeyEntropy::Low);
    let msg = pad(&String::from("test"), cfg.max_msg_len());
    let cipher = LogEntry::new(&msg, &key_pair, cfg.hmac_alg).expect("Could not create entry.")
        .get_cipher();
    let mut measurements = [0; NUM_TESTS];
    
    for i in 0..NUM_TESTS {
        let start = PreciseTime::now();
        
        for _ in 0..n {
            let mac1 = hmac(&cipher, &key_pair.encryption, hmac_alg);
            hmac(&mac1, &key_pair.signature, hmac_alg);
        }
        measurements[i] = start.to(PreciseTime::now()).num_nanoseconds().unwrap();
    }
    let mean = mean(&measurements);
    
    (key, mean, std_dev(&measurements, mean))
}

fn encrypt_n_messages(n: usize, cfg: Config) -> (String, i64, i64) {
    let msg_len = cfg.max_msg_len();
    let key = format!("encrypt_{}_messages_msg_len_{}", n, msg_len);
    let key_pair = derive_key_pair(&[0xff; 64], KeyEntropy::Low);
    let msg = pad(&String::from("test"), cfg.max_msg_len());
    let mut measurements = [0; NUM_TESTS];
    
    for i in 0..NUM_TESTS {
        let start = PreciseTime::now();
        
        for _ in 0..n {
            encrypt(&msg, &key_pair.encryption).unwrap();
        }
        measurements[i] = start.to(PreciseTime::now()).num_nanoseconds().unwrap();
    }
    let mean = mean(&measurements);
    
    (key, mean, std_dev(&measurements, mean))
}

fn do_n_hashchain_updates(n: usize) -> (String, i64, i64) {
    let key = format!("do_{}_hashchain_updates", n);
    let mut chain = HashChain::new(&[0xff; 64]);
    let mut measurements = [0; NUM_TESTS];
    
    for i in 0..NUM_TESTS {
        let start = PreciseTime::now();
        
        for _ in 0..n {
            chain.evolve()
        }
        measurements[i] = start.to(PreciseTime::now()).num_nanoseconds().unwrap();
    }
    let mean = mean(&measurements);
    
    (key, mean, std_dev(&measurements, mean))
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
