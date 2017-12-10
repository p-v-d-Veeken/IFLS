extern crate crypto;

use log::log_file::LogFile;
use self::crypto::symmetriccipher::SymmetricCipherError;

pub struct Interpreter {
    pub logfile: LogFile
}

impl<'a> Interpreter {
    pub fn new(path: &'a str) -> Interpreter {
        let logfile = LogFile::open(path);
        
        Interpreter { logfile }
    }
    
    pub fn get_plaintexts(&mut self,
                          decryption_keys: &Vec<&Vec<u8>>
    ) -> Vec<Result<String, SymmetricCipherError>> {
        let mut plaintexts: Vec<Result<String, SymmetricCipherError>> = vec![];
        
        self.logfile.by_ref().enumerate()
            .skip(1)
            .map(|(i, entry)| entry.decrypt(decryption_keys[i - 1]))
            .for_each(|res| plaintexts.push(res));
        
        plaintexts
    }
}

#[cfg(test)]
mod tests {
    use app::interpreter::Interpreter;
    use app::logger::{Logger, LogError};
    use cfg::settings::{HmacAlgorithm, KeyEntropy};
    use cfg::config::Config;
    use util::hash::HashChain;
    use util::key_derivation::derive_key_pair;
    use util::misc::root_from_str;
    use std::fs;
    use std::path::Path;
    
    #[test]
    fn get_plaintexts_hmac_sha256() {
        let configs = vec![
            Config::new(3, KeyEntropy::High, HmacAlgorithm::HmacSha256),
            Config::new(4, KeyEntropy::Medium, HmacAlgorithm::HmacSha256),
            Config::new(5, KeyEntropy::Low, HmacAlgorithm::HmacSha256),
        ];
        let path = "get_plaintexts_hmac_sha256";
        let root_str = String::from("👿😊😀😃😫😄😈😖😇😣😁😩😂😆😅💩");
        
        configs.iter()
            .for_each(|config| test_get_plaintexts(path, &root_str, *config, MESSAGES.len() as u8));
    }
    
    #[test]
    fn get_plaintexts_hmac_sha512() {
        let configs = vec![
            Config::new(3, KeyEntropy::High, HmacAlgorithm::HmacSha512),
            Config::new(4, KeyEntropy::Medium, HmacAlgorithm::HmacSha512),
            Config::new(5, KeyEntropy::Low, HmacAlgorithm::HmacSha512),
        ];
        let path = "get_plaintexts_hmac_sha512";
        let root_str = String::from("👿😀😃😄😫😈😖😇😣😁😩😂😆😅💩😊");
        
        configs.iter()
            .for_each(|config| test_get_plaintexts(path, &root_str, *config, MESSAGES.len() as u8));
    }
    
    #[test]
    fn get_plaintexts_key_entropy_low() {
        let configs = vec![
            Config::new(3, KeyEntropy::Low, HmacAlgorithm::HmacSha512),
            Config::new(4, KeyEntropy::Low, HmacAlgorithm::HmacSha256),
        ];
        let path = "get_plaintexts_key_entropy_low";
        let root_str = String::from("👿😀😃😄😫😈😖😇😣😁😩😂😆😅💩😊");
        
        configs.iter()
            .for_each(|config| test_get_plaintexts(path, &root_str, *config, MESSAGES.len() as u8));
    }
    
    #[test]
    fn get_plaintexts_key_entropy_med() {
        let configs = vec![
            Config::new(3, KeyEntropy::Medium, HmacAlgorithm::HmacSha512),
            Config::new(4, KeyEntropy::Medium, HmacAlgorithm::HmacSha256),
        ];
        let path = "get_plaintexts_key_entropy_med";
        let root_str = String::from("👿😈😀😃😄😫😖💩😇😣😁😩😂😆😅😊");
        
        configs.iter()
            .for_each(|config| test_get_plaintexts(path, &root_str, *config, MESSAGES.len() as u8));
    }
    
    #[test]
    fn get_plaintexts_key_entropy_high() {
        let configs = vec![
            Config::new(3, KeyEntropy::High, HmacAlgorithm::HmacSha512),
            Config::new(4, KeyEntropy::High, HmacAlgorithm::HmacSha256),
        ];
        let path = "get_plaintexts_key_entropy_high";
        let root_str = String::from("👿😀😃😄😫😈💩😖😣😁😩😂😆😅😊😇");
        
        configs.iter()
            .for_each(|config| test_get_plaintexts(path, &root_str, *config, MESSAGES.len() as u8));
    }
    
    fn test_get_plaintexts(path: &'static str, root_str: &String, config: Config, msg_count: u8) {
        if Path::new(path).exists() {
            fs::remove_file(&path).expect("Failed to delete leftover test file.");
        }
        let secret = String::from(path);
        let root = root_from_str(root_str);
        let keys = get_decryption_keys(&root, msg_count, config.key_entropy);
        let mut logger = Logger::new(config, &path, &secret, &root);
        
        for i in 0..msg_count { logger.log(&String::from(MESSAGES[i as usize])).unwrap() }
        
        let mut interpreter = Interpreter::new(path);
        let keys_borrowed: Vec<&Vec<u8>> = keys.iter()
            .map(|key| key)
            .collect();
        
        interpreter.get_plaintexts(&keys_borrowed).iter()
            .enumerate()
            .for_each(|(i, decryption_result)| {
                match *decryption_result {
                    Ok(ref plaintext) => assert_eq!(String::from(MESSAGES[i]), *plaintext),
                    Err(ref e) => {
                        fs::remove_file(&path).expect("Failed to delete test logfile.");
                        panic!("{}", LogError::Encryption(*e))
                    }
                }
            });
        fs::remove_file(&path).expect("Failed to delete test logfile.");
    }
    
    fn get_decryption_keys(root: &[u8; 64], amount: u8, entropy: KeyEntropy) -> Vec<Vec<u8>> {
        let mut chain = HashChain::new(root);
        let mut keys: Vec<Vec<u8>> = vec![];
        
        for _ in 0..amount {
            chain.evolve();
            keys.push(derive_key_pair(&chain.get_node(), entropy).encryption);
        }
        
        keys
    }
    
    const MESSAGES: [&'static str; 5] = [
        "WHAT IS LOVE!?.",
        "Two gorillion buttcoins.",
        "SELL IT ALL.",
        "To the moon!",
        "#Lamboland.",
    ];
}
