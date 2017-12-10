use cfg::settings::{KeyEntropy, HmacAlgorithm};

pub const HEADER_BYTE_LEN: usize = 3;
pub const MAX_CIPHER_BLOCK_LEN: usize = 20;
pub const ENTRY_MAX_BYTE_SIZE: usize = MAX_CIPHER_BLOCK_LEN * 16 + 64;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Config {
    pub cipher_block_len: u8,
    pub key_entropy: KeyEntropy,
    pub hmac_alg: HmacAlgorithm,
}

impl Config {
    pub fn new(cipher_block_len: u8,
               key_entropy: KeyEntropy,
               hmac_alg: HmacAlgorithm,
    ) -> Config {
        if cipher_block_len == 0 { panic!("The minimum cipher block length is 1.") }
        if cipher_block_len as usize > MAX_CIPHER_BLOCK_LEN {
            panic!("The maximum cipher block length is {}.", MAX_CIPHER_BLOCK_LEN)
        }
        
        Config { cipher_block_len, key_entropy, hmac_alg }
    }
    
    pub fn from_bytes(bytes: [u8; HEADER_BYTE_LEN as usize]) -> Config {
        if bytes[0] == 0 { panic!("Illegal value for the cipher block length: 0.") }
        
        Config {
            cipher_block_len: bytes[0],
            key_entropy: Config::key_entropy_from_byte(bytes[1]),
            hmac_alg: Config::hmac_alg_from_byte(bytes[2]),
        }
    }
    
    pub fn to_bytes(&self) -> [u8; 3] {
        [
            self.cipher_block_len,
            Config::key_entropy_to_byte(self.key_entropy),
            Config::hmac_alg_to_byte(self.hmac_alg),
        ]
    }
    
    pub fn cipher_byte_size(&self) -> usize { (self.cipher_block_len as usize * 16) as usize }
    
    pub fn max_msg_len(&self) -> usize { (self.cipher_block_len as usize * 16 - 1) as usize }
    
    pub fn sign_byte_size(&self) -> usize {
        match self.hmac_alg {
            HmacAlgorithm::HmacSha512 => 64,
            HmacAlgorithm::HmacSha256 => 32,
        }
    }
    
    pub fn entry_byte_size(&self) -> usize { self.cipher_byte_size() + self.sign_byte_size() }
    
    pub fn key_entropy_from_byte(byte: u8) -> KeyEntropy {
        match byte {
            0 => KeyEntropy::High,
            1 => KeyEntropy::Medium,
            2 => KeyEntropy::Low,
            _ => panic!("Invalid value for key_entropy byte: {}", byte)
        }
    }
    
    pub fn key_entropy_to_byte(key_entropy: KeyEntropy) -> u8 {
        match key_entropy {
            KeyEntropy::High => 0,
            KeyEntropy::Medium => 1,
            KeyEntropy::Low => 2,
        }
    }
    
    pub fn hmac_alg_to_byte(hmac_alg: HmacAlgorithm) -> u8 {
        match hmac_alg {
            HmacAlgorithm::HmacSha512 => 0,
            HmacAlgorithm::HmacSha256 => 1,
        }
    }
    
    pub fn hmac_alg_from_byte(byte: u8) -> HmacAlgorithm {
        match byte {
            0 => HmacAlgorithm::HmacSha512,
            1 => HmacAlgorithm::HmacSha256,
            _ => panic!("Invalid value for hmac_alg byte: {}", byte)
        }
    }
}

#[cfg(test)]
mod tests {
    use cfg::config::Config;
    use cfg::settings::{KeyEntropy, HmacAlgorithm};
    
    #[test]
    pub fn config_from_bytes() {
        let cfgs: Vec<Config> = vec![
            [1, 0, 0],
            [2, 0, 1],
            [3, 1, 0],
            [4, 1, 1],
            [5, 2, 0],
            [6, 2, 1],
        ].iter()
            .map(|bytes| Config::from_bytes(*bytes))
            .collect();
        
        let cfgs_expect: Vec<Config> = vec![
            Config::new(1, KeyEntropy::High, HmacAlgorithm::HmacSha512),
            Config::new(2, KeyEntropy::High, HmacAlgorithm::HmacSha256),
            Config::new(3, KeyEntropy::Medium, HmacAlgorithm::HmacSha512),
            Config::new(4, KeyEntropy::Medium, HmacAlgorithm::HmacSha256),
            Config::new(5, KeyEntropy::Low, HmacAlgorithm::HmacSha512),
            Config::new(6, KeyEntropy::Low, HmacAlgorithm::HmacSha256),
        ];
        
        cfgs_expect.iter()
            .enumerate()
            .for_each(|(i, cfg)| assert_eq!(
                *cfg,
                cfgs[i]
            ))
    }
    
    #[test]
    pub fn config_to_bytes() {
        let cfg_bytes: Vec<[u8; 3]> = vec![
            Config::new(1, KeyEntropy::High, HmacAlgorithm::HmacSha512).to_bytes(),
            Config::new(2, KeyEntropy::High, HmacAlgorithm::HmacSha256).to_bytes(),
            Config::new(3, KeyEntropy::Medium, HmacAlgorithm::HmacSha512).to_bytes(),
            Config::new(4, KeyEntropy::Medium, HmacAlgorithm::HmacSha256).to_bytes(),
            Config::new(5, KeyEntropy::Low, HmacAlgorithm::HmacSha512).to_bytes(),
            Config::new(6, KeyEntropy::Low, HmacAlgorithm::HmacSha256).to_bytes(),
        ];
        let bytes_expect: Vec<[u8; 3]> = vec![
            [1, 0, 0],
            [2, 0, 1],
            [3, 1, 0],
            [4, 1, 1],
            [5, 2, 0],
            [6, 2, 1],
        ];
        
        bytes_expect.iter()
            .enumerate()
            .for_each(|(i, bytes)| assert_eq!(
                *bytes,
                cfg_bytes[i]
            ))
    }
    
    #[test]
    pub fn max_msg_len() {
        let cfgs: Vec<Config> = vec![
            Config::new(1, KeyEntropy::High, HmacAlgorithm::HmacSha512),
            Config::new(2, KeyEntropy::High, HmacAlgorithm::HmacSha256),
            Config::new(3, KeyEntropy::Medium, HmacAlgorithm::HmacSha512),
            Config::new(4, KeyEntropy::Medium, HmacAlgorithm::HmacSha256),
            Config::new(5, KeyEntropy::Low, HmacAlgorithm::HmacSha512),
            Config::new(6, KeyEntropy::Low, HmacAlgorithm::HmacSha256),
        ];
        let max_msg_len_expect = vec![15, 31, 47, 63, 79, 95];
        
        max_msg_len_expect.iter()
            .enumerate()
            .for_each(|(i, max_msg_len)| assert_eq!(*max_msg_len, cfgs[i].max_msg_len()))
    }
    
    #[test]
    pub fn key_entropy_from_byte() {
        let key_entropies: Vec<KeyEntropy> = vec![0u8, 1u8, 2u8].iter()
            .map(|byte| Config::key_entropy_from_byte(*byte))
            .collect();
        
        vec![KeyEntropy::High, KeyEntropy::Medium, KeyEntropy::Low].iter()
            .enumerate()
            .for_each(|(i, key_entropy)| assert_eq!(
                *key_entropy,
                key_entropies[i]
            ))
    }
    
    #[test]
    pub fn key_entropy_to_byte() {
        let key_bytes: Vec<u8> = vec![KeyEntropy::High, KeyEntropy::Medium, KeyEntropy::Low].iter()
            .map(|key_entropy| Config::key_entropy_to_byte(*key_entropy))
            .collect();
        
        vec![0, 1, 2].iter()
            .enumerate()
            .for_each(|(i, key_byte)| assert_eq!(
                *key_byte,
                key_bytes[i]
            ))
    }
    
    #[test]
    pub fn hmac_alg_from_byte() {
        let hmac_algs: Vec<HmacAlgorithm> = vec![0u8, 1u8].iter()
            .map(|byte| Config::hmac_alg_from_byte(*byte))
            .collect();
        
        vec![HmacAlgorithm::HmacSha512, HmacAlgorithm::HmacSha256].iter()
            .enumerate()
            .for_each(|(i, hmac_alg)| assert_eq!(
                *hmac_alg,
                hmac_algs[i]
            ))
    }
    
    #[test]
    pub fn hmac_alg_to_byte() {
        let alg_bytes: Vec<u8> = vec![HmacAlgorithm::HmacSha512, HmacAlgorithm::HmacSha256].iter()
            .map(|hmac_alg| Config::hmac_alg_to_byte(*hmac_alg))
            .collect();
        
        vec![0, 1].iter()
            .enumerate()
            .for_each(|(i, alg_byte)| assert_eq!(
                *alg_byte,
                alg_bytes[i]
            ))
    }
}
