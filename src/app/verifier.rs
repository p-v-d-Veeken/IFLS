extern crate crypto;

use cfg::settings::HmacAlgorithm;
use log::log_file::LogFile;
use log::log_entry::LogEntry;
use util::crypt::decrypt;
use util::hash::hmac;
use util::misc::pad;
use std::fmt;
use self::crypto::symmetriccipher::SymmetricCipherError;

pub struct Verifier {
    logfile: LogFile,
}

impl Verifier {
    pub fn new(logfile_path: &str) -> Verifier {
        Verifier { logfile: LogFile::open(logfile_path) }
    }
    
    pub fn verify(mut self,
                  secret: &String,
                  signature_keys: &Vec<&Vec<u8>>,
                  first_decryption_key: &Vec<u8>,
    ) -> Result<(), VerificationError> {
        if signature_keys.len() > self.logfile.entry_count() {
            return Err(VerificationError::InputError("No. of supplied keys != no. of entries."));
        }
        if self.logfile.by_ref().is_empty() {
            return Err(VerificationError::InputError("Log file is empty."));
        }
        let padded_secret = pad(secret, self.logfile.config.max_msg_len());
        let first_entry = &self.logfile.peek().unwrap();
        
        Verifier::verify_secret(&padded_secret, &first_entry, first_decryption_key)?;
        self.verify_subset(signature_keys, 0)?;
        
        Ok(())
    }
    
    fn verify_secret(
        secret: &String,
        first_entry: &LogEntry,
        decryption_key: &Vec<u8>
    ) -> Result<(), VerificationError> {
        let m = match decrypt(&first_entry.get_cipher(), decryption_key) {
            Ok(m) => m,
            Err(e) => return Err(VerificationError::DecryptionError(0usize, e)),
        };
        if secret.as_bytes().to_vec() != m { return Err(VerificationError::SecretError); }
        
        Ok(())
    }
    
    pub fn verify_subset(mut self,
                         signature_keys: &Vec<&Vec<u8>>,
                         start_index: usize
    ) -> Result<(), VerificationError> {
        if self.logfile.by_ref().entry_count() <= start_index {
            return Err(VerificationError::InputError("Start index too large."));
        }
        if signature_keys.is_empty() {
            return Err(VerificationError::InputError("Signature key set was empty."));
        }
        if start_index + signature_keys.len() > self.logfile.by_ref().entry_count() {
            return Err(VerificationError::InputError("More keys than log entries supplied."));
        }
        let alg = self.logfile.config.hmac_alg;
        let entry_count = self.logfile.by_ref().entry_count();
        let mut entry = None;
        let mut i = 0usize;
        
        for next_entry in self.logfile.by_ref() {
            if i > start_index && entry.as_ref().is_some() {
                if i - start_index == signature_keys.len() { break }
                
                let keys: [&Vec<u8>; 2] = [
                    &signature_keys[i - start_index - 1],
                    &signature_keys[i - start_index],
                ];
                Verifier::verify_entry(entry.as_ref().unwrap(), Some(&next_entry), &keys, i, alg)?
            }
            entry = Some(next_entry);
            i += 1;
            
            if i == entry_count - 1 && i - start_index < signature_keys.len() {
                let keys = [signature_keys[i - start_index], &vec![]];
                
                Verifier::verify_entry(entry.as_ref().unwrap(), None, &keys, i, alg)?
            }
        }
        
        Ok(())
    }
    
    fn verify_entry(
        entry: &LogEntry,
        next_entry: Option<&LogEntry>,
        signature_keys: &[&Vec<u8>; 2],
        i: usize,
        hmac_alg: HmacAlgorithm,
    ) -> Result<(), VerificationError> {
        let mut signature = hmac(&entry.get_cipher(), &signature_keys[0], hmac_alg);
        
        if next_entry.is_some() {
            signature.extend(next_entry.unwrap().get_cipher());
            signature = hmac(&signature, &signature_keys[1], hmac_alg);
        }
        
        if signature != entry.get_signature() {
            return Err(VerificationError::InvalidSignatureError(i));
        }
        
        Ok(())
    }
}

#[derive(Debug)]
pub enum VerificationError {
    SecretError,
    InputError(&'static str),
    InvalidSignatureError(usize),
    DecryptionError(usize, SymmetricCipherError),
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            VerificationError::SecretError => write!(f, "Incorrect secret."),
            VerificationError::InputError(e) => write!(f, "{}", e),
            VerificationError::InvalidSignatureError(i) => {
                write!(f, "Entry {}: Incorrect signature.", i)
            }
            VerificationError::DecryptionError(i, ref e) => {
                write!(f, "Entry {}: Decryption error ({:?}).", i, e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate base64;
    
    use app::logger::Logger;
    use app::verifier::Verifier;
    use cfg::settings::{HmacAlgorithm, KeyEntropy};
    use cfg::config::Config;
    use util::hash::HashChain;
    use util::key_derivation::derive_key_pair;
    use util::misc::root_from_str;
    use std::fs;
    use std::path::Path;
    
    #[test]
    fn incorrect_secret() {
        let config = Config::new(4, KeyEntropy::Medium, HmacAlgorithm::HmacSha256);
        let path = "test_incorrect_secret";
        let secret = String::from(path);
        let root = [0u8; 64];
        let keys = derive_key_pair(&root, KeyEntropy::Medium);
        let signature_keys = vec![&keys.signature];
        
        Logger::new(config, &path, &secret, &root);
        
        let verifier = Verifier::new(&path);
        
        match verifier.verify(&String::from("wrong secret"), &signature_keys, &keys.encryption) {
            Ok(_) => {
                fs::remove_file(&path).expect("Failed to delete test logfile.");
                panic!("Verifier accepted incorrect secret.")
            }
            Err(e) => {
                fs::remove_file(&path).expect("Failed to delete test logfile.");
                
                assert_eq!("Incorrect secret.", format!("{}", e))
            }
        }
    }
    
    #[test]
    fn test_verify_secret() {
        let config = Config::new(4, KeyEntropy::Medium, HmacAlgorithm::HmacSha256);
        let path = "test_verify_secret";
        let root_str = String::from("😀💩😃😫😄😈😖👿😇😣😊😁😩😂😆😅");
        
        test_verify(path, &root_str, config, 1)
    }
    
    #[test]
    fn verify_hmac_sha_256() {
        let configs = vec![
            Config::new(3, KeyEntropy::High, HmacAlgorithm::HmacSha256),
            Config::new(4, KeyEntropy::Medium, HmacAlgorithm::HmacSha256),
            Config::new(5, KeyEntropy::Low, HmacAlgorithm::HmacSha256),
        ];
        let path = "verify_hmac_sha_256";
        let root_str = String::from("😀💩😃😫😄😈😖👿😇😣😊😁😩😂😆😅");
        
        configs.iter()
            .for_each(|config| test_verify(path, &root_str, *config, MESSAGES.len() as u8));
    }
    
    #[test]
    fn verify_hmac_sha_512() {
        let configs = vec![
            Config::new(3, KeyEntropy::High, HmacAlgorithm::HmacSha512),
            Config::new(4, KeyEntropy::Medium, HmacAlgorithm::HmacSha512),
            Config::new(5, KeyEntropy::Low, HmacAlgorithm::HmacSha512),
        ];
        let path = "verify_hmac_sha_512";
        let root_str = String::from("😀😃😫💩😄😈😖👿😊😁😩😇😣😆😅😂");
        
        configs.iter()
            .for_each(|config| test_verify(path, &root_str, *config, MESSAGES.len() as u8));
    }
    
    #[test]
    fn verify_key_entropy_low() {
        let configs = vec![
            Config::new(3, KeyEntropy::Low, HmacAlgorithm::HmacSha512),
            Config::new(4, KeyEntropy::Low, HmacAlgorithm::HmacSha256),
        ];
        let path = "verify_key_entropy_low";
        let root_str = String::from("😀😃😫💩😄👿😊😁😩😇😈😖😣😆😅😂");
        
        configs.iter()
            .for_each(|config| test_verify(path, &root_str, *config, MESSAGES.len() as u8));
    }
    
    #[test]
    fn verify_key_entropy_med() {
        let configs = vec![
            Config::new(3, KeyEntropy::Medium, HmacAlgorithm::HmacSha512),
            Config::new(4, KeyEntropy::Medium, HmacAlgorithm::HmacSha256),
        ];
        let path = "verify_key_entropy_med";
        let root_str = String::from("😀😃😫😄👿😊😁😩😇😈😖😣😆😅😂💩");
        
        configs.iter()
            .for_each(|config| test_verify(path, &root_str, *config, MESSAGES.len() as u8));
    }
    
    #[test]
    fn verify_key_entropy_high() {
        let configs = vec![
            Config::new(3, KeyEntropy::Medium, HmacAlgorithm::HmacSha512),
            Config::new(4, KeyEntropy::Medium, HmacAlgorithm::HmacSha256),
        ];
        let path = "verify_key_entropy_high";
        let root_str = String::from("😀😃😫👿😇😈😄😊😁😩😖😣😆😅😂💩");
        
        configs.iter()
            .for_each(|config| test_verify(path, &root_str, *config, MESSAGES.len() as u8));
    }
    
    fn test_verify(path: &'static str, root_str: &String, config: Config, msg_count: u8) {
        if Path::new(path).exists() {
            fs::remove_file(&path).expect("Failed to delete leftover test file.");
        }
        let secret = String::from(path);
        let root = root_from_str(root_str);
        let first_decrypt_key = derive_key_pair(&root, config.key_entropy).encryption;
        let keys = get_signature_keys(&root, msg_count, config.key_entropy);
        let mut logger = Logger::new(config, &path, &secret, &root);
        
        for i in 0..msg_count { logger.log(&String::from(MESSAGES[i as usize])).unwrap() }
        
        let verifier = Verifier::new(path);
        let keys_borrowed: Vec<&Vec<u8>> = keys.iter()
            .map(|key| key)
            .collect();
        
        match verifier.verify(&secret, &keys_borrowed, &first_decrypt_key) {
            Ok(_) => {
                fs::remove_file(&path).expect("Failed to delete test logfile.");
            }
            Err(e) => {
                fs::remove_file(&path).expect("Failed to delete test logfile.");
                
                panic!("{}", e)
            }
        }
    }
    
    fn get_signature_keys(root: &[u8; 64], amount: u8, entropy: KeyEntropy) -> Vec<Vec<u8>> {
        let mut chain = HashChain::new(root);
        let mut keys: Vec<Vec<u8>> = vec![];
        
        for _ in 0..amount {
            keys.push(derive_key_pair(&chain.get_node(), entropy).signature);
            chain.evolve()
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
