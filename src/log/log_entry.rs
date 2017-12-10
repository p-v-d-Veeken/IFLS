extern crate base64;
extern crate crypto;

use cfg::config::Config;
use cfg::settings::HmacAlgorithm;
use util::crypt::{decrypt, encrypt};
use util::hash::hmac;
use util::key_derivation::KeyPair;
use util::misc::remove_padding;
use std::fmt;
use self::crypto::symmetriccipher::SymmetricCipherError;

#[derive(Eq, PartialEq, Clone)]
pub struct LogEntry {
    ciphertext: Vec<u8>,
    signature: Vec<u8>,
}

impl LogEntry {
    pub fn new(text: &String,
               key_pair: &KeyPair,
               hmac_alg: HmacAlgorithm,
    ) -> Result<LogEntry, SymmetricCipherError> {
        let ciphertext = encrypt(text, &key_pair.encryption)?;
        let signature = hmac(&ciphertext, &key_pair.signature, hmac_alg);
        
        Ok(LogEntry {
            ciphertext,
            signature,
        })
    }
    
    pub fn from_bytes(bytes: Vec<u8>, config: &Config) -> LogEntry {
        if bytes.len() < config.entry_byte_size() {
            panic!("Malformed log entry!")
        }
        
        LogEntry {
            ciphertext: bytes[0..config.cipher_byte_size()].to_vec(),
            signature: bytes[config.cipher_byte_size()..config.entry_byte_size()].to_vec()
        }
    }
    
    pub fn set_next_cipher(&mut self,
                           next_ciphertext: &Vec<u8>,
                           next_signature_key: &Vec<u8>,
                           hmac_alg: HmacAlgorithm,
    ) {
        let mut concat = self.signature.to_vec();
        
        concat.extend(next_ciphertext.iter());
        self.signature = hmac(&concat, next_signature_key, hmac_alg);
    }
    
    pub fn decrypt(&self, decryption_key: &Vec<u8>) -> Result<String, SymmetricCipherError> {
        let bytes = decrypt(&self.ciphertext, decryption_key)?;
        let text = String::from_utf8(bytes)
            .expect("Could not create utf8 string from decrypted bytes.");
        
        Ok(remove_padding(&text))
    }
    
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = self.ciphertext.clone();
        
        bytes.extend(self.signature.clone());
        bytes
    }
    
    pub fn get_signature(&self) -> Vec<u8> { self.signature.clone() }
    
    pub fn get_cipher(&self) -> Vec<u8> { self.ciphertext.clone() }
}

impl fmt::Debug for LogEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "LogEntry: {{\n\tC:{},\n\tH:{}\n}}",
            base64::encode(&self.ciphertext),
            base64::encode(&self.signature)
        )
    }
}
