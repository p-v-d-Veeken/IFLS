extern crate crypto;

use cfg::config::Config;
use log::log_file::LogFile;
use log::log_entry::LogEntry;
use util::key_derivation::derive_key_pair;
use util::hash::HashChain;
use util::misc::pad;
use std::io::Error;
use std::fmt;
use self::crypto::symmetriccipher::SymmetricCipherError;

pub struct Logger {
    pub logfile: LogFile,
    hash_chain: HashChain,
    last_log_entry: Option<LogEntry>,
}

impl Logger {
    pub fn new(config: Config,
               logfile_path: &str,
               secret: &String,
               hash_chain_root: &[u8; 64],
    ) -> Logger {
        if secret.is_empty() { panic!("{}", LogError::InvalidSecret); }
        
        let mut logger = Logger {
            logfile: LogFile::new(config, logfile_path),
            hash_chain: HashChain::new(hash_chain_root),
            last_log_entry: None,
        };
        logger.log(secret).expect("Could not log initial secret to log file.");
        
        logger
    }
    
    pub fn log(&mut self, text: &String) -> Result<(), LogError> {
        if text.is_empty() { return Err(LogError::EmptyLogLine); }
        if text.len() > self.logfile.config.max_msg_len() { return Err(LogError::MessageTooLong); }
        
        let hmac_alg = self.logfile.config.hmac_alg;
        let padded_text = pad(text, self.logfile.config.max_msg_len());
        let node = &self.hash_chain.get_node();
        let keys = derive_key_pair(node, self.logfile.config.key_entropy);
        let new_entry = match LogEntry::new(&padded_text, &keys, hmac_alg) {
            Ok(entry) => entry,
            Err(e) => return Err(LogError::Encryption(e)),
        };
        let mut bytes: Vec<u8> = vec![];
        
        if self.last_log_entry.is_some() {
            let last_log_entry: &mut LogEntry = self.last_log_entry.as_mut().unwrap();
            
            last_log_entry.set_next_cipher(&new_entry.get_cipher(), &keys.signature, hmac_alg);
            bytes.extend(last_log_entry.get_signature().to_vec())
        }
        bytes.extend(new_entry.as_bytes());
        
        match self.logfile.write_log_entry(bytes) {
            Ok(_) => (),
            Err(e) => return Err(LogError::Io(e))
        };
        self.hash_chain.evolve();
        self.last_log_entry = Some(new_entry);
        
        Ok(())
    }
}

#[derive(Debug)]
pub enum LogError {
    Io(Error),
    Encryption(SymmetricCipherError),
    InvalidSecret,
    EmptyLogLine,
    MessageTooLong,
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LogError::Io(ref e) => e.fmt(f),
            LogError::Encryption(ref e) => write!(f, "Encryption error: {:?}", e),
            LogError::InvalidSecret => write!(f, "Secret can not be empty."),
            LogError::EmptyLogLine => write!(f, "Log event was empty string."),
            LogError::MessageTooLong => write!(f, "Message was too long.")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use app::logger::Logger;
    use cfg::config::Config;
    use cfg::settings::{KeyEntropy, HmacAlgorithm};
    use log::log_entry::LogEntry;
    use util::key_derivation::{derive_key_pair, KeyPair};
    use util::hash::HashChain;
    use util::misc::{pad, root_from_str};
    
    #[test]
    #[should_panic]
    fn invalid_secret() {
        let config = Config::new(4, KeyEntropy::Medium, HmacAlgorithm::HmacSha256);
        let secret = String::from("");
        let root = [0u8; 64];
        
        Logger::new(config, ".", &secret, &root);
        
        assert!(false)
    }
    
    #[test]
    fn log_empty_message() {
        let config = Config::new(4, KeyEntropy::Medium, HmacAlgorithm::HmacSha256);
        let path = "test_log_empty_message";
        let secret = String::from("secret");
        let root = [0u8; 64];
        let mut logger = Logger::new(config, &path, &secret, &root);
        let message = String::from("");
        
        match logger.log(&message) {
            Ok(_) => {
                fs::remove_file(&path).expect("Failed to delete test logfile.");
                panic!("Logger accepted empty message")
            }
            Err(e) => {
                fs::remove_file(&path).expect("Failed to delete test logfile.");
                
                if format!("{}", e) != "Log event was empty string." {
                    panic!("Wrong error type was returned.")
                }
            }
        }
    }
    
    #[test]
    fn log_too_long_message() {
        let config = Config::new(3, KeyEntropy::Medium, HmacAlgorithm::HmacSha256);
        let path = "test_log_too_long_message";
        let secret = String::from("secret");
        let root = [0u8; 64];
        let mut logger = Logger::new(config, &path, &secret, &root);
        let log_line = String::from("This is a way too long message that should not be logged.");
        
        match logger.log(&log_line) {
            Ok(_) => {
                fs::remove_file(&path).expect("Failed to delete test logfile.");
                panic!("Logger accepted too long message")
            }
            Err(e) => {
                fs::remove_file(&path).expect("Failed to delete test logfile.");
                
                if format!("{}", e) != "Message was too long." {
                    panic!("Wrong error type was returned.")
                }
            }
        }
    }
    
    #[test]
    fn log_hmac_sha_256() {
        let configs = vec![
            Config::new(3, KeyEntropy::High, HmacAlgorithm::HmacSha256),
            Config::new(4, KeyEntropy::Medium, HmacAlgorithm::HmacSha256),
            Config::new(5, KeyEntropy::Low, HmacAlgorithm::HmacSha256),
        ];
        let path = "test_log_hmac_sha_256";
        let root_str = String::from("😀😃😄😁😆😅😂😊😇😣😖😫😩💩😈👿");
        
        configs.iter()
            .for_each(|config| test_log(path, &root_str, *config))
    }
    
    #[test]
    fn log_hmac_sha_512() {
        let configs = vec![
            Config::new(3, KeyEntropy::High, HmacAlgorithm::HmacSha512),
            Config::new(4, KeyEntropy::Medium, HmacAlgorithm::HmacSha512),
            Config::new(5, KeyEntropy::Low, HmacAlgorithm::HmacSha512),
        ];
        let path = "test_log_hmac_sha_512";
        let root_str = String::from("😖😫😩😀😃😄💩😈👿😂😊😁😆😅😇😣");
        
        configs.iter()
            .for_each(|config| test_log(path, &root_str, *config))
    }
    
    #[test]
    fn log_key_entropy_low() {
        let configs = vec![
            Config::new(3, KeyEntropy::Low, HmacAlgorithm::HmacSha512),
            Config::new(4, KeyEntropy::Low, HmacAlgorithm::HmacSha256),
        ];
        let path = "test_log_key_entropy_low";
        let root_str = String::from("😀😃😄💩😈😖😫😊😁😩👿😂😆😅😇😣");
        
        configs.iter()
            .for_each(|config| test_log(path, &root_str, *config))
    }
    
    #[test]
    fn log_key_entropy_med() {
        let configs = vec![
            Config::new(3, KeyEntropy::Medium, HmacAlgorithm::HmacSha512),
            Config::new(4, KeyEntropy::Medium, HmacAlgorithm::HmacSha256),
        ];
        let path = "test_log_key_entropy_med";
        let root_str = String::from("😀😈😖😫😃😄💩😩😊😁👿😂😆😅😇😣");
        
        configs.iter()
            .for_each(|config| test_log(path, &root_str, *config))
    }
    
    #[test]
    fn log_key_entropy_high() {
        let configs = vec![
            Config::new(3, KeyEntropy::High, HmacAlgorithm::HmacSha512),
            Config::new(4, KeyEntropy::High, HmacAlgorithm::HmacSha256),
        ];
        let path = "test_log_key_entropy_high";
        let root_str = String::from("😀😃😄💩😈😖😫😊😁😩👿😇😣😂😆😅");
        
        configs.iter()
            .for_each(|config| test_log(path, &root_str, *config))
    }
    
    fn get_key_pairs(root: &[u8; 64], amount: u8, entropy: KeyEntropy) -> Vec<KeyPair> {
        let mut chain = HashChain::new(root);
        let mut keys: Vec<KeyPair> = vec![];
        
        for _ in 0..amount {
            keys.push(derive_key_pair(&chain.get_node(), entropy));
            chain.evolve()
        }
        
        keys
    }
    
    fn test_log(path: &'static str, root_str: &String, config: Config) {
        if Path::new(path).exists() {
            fs::remove_file(&path).expect("Failed to delete leftover test file.");
        }
        let hmac_alg = config.hmac_alg;
        let secret = pad(&String::from(path), config.max_msg_len());
        let root = root_from_str(root_str);
        let mut logger = Logger::new(config, &path, &secret, &root);
        let key_pairs = get_key_pairs(&root, MESSAGES.len() as u8, config.key_entropy);
        let mut entries: Vec<LogEntry> = vec![
            LogEntry::new(&secret, &key_pairs[0], config.hmac_alg).unwrap()
        ];
        
        for (i, key_pair) in key_pairs.iter().enumerate().skip(1) {
            let msg = pad(&String::from(MESSAGES[i]), config.max_msg_len());
            let entry = LogEntry::new(&msg, key_pair, config.hmac_alg).unwrap();
            let j = entries.len() - 1;
            
            entries[j].set_next_cipher(&entry.get_cipher(), &key_pair.signature, hmac_alg);
            
            match logger.log(&msg) {
                Ok(_) => (),
                Err(_) => {
                    fs::remove_file(&path).expect("Failed to delete test logfile.");
                    
                    panic!("Error while logging!")
                }
            }
            entries.push(entry);
        }
        logger.logfile.enumerate()
            .for_each(|(i, entry)| assert_eq!(entries[i], entry));
        
        fs::remove_file(&path).expect("Failed to delete test logfile.");
    }
    
    const MESSAGES: [&'static str; 5] = [
        "WHAT IS LOVE!?.",
        "Two gorillion buttcoins.",
        "SELL IT ALL.",
        "To the moon!",
        "#Lamboland.",
    ];
}
