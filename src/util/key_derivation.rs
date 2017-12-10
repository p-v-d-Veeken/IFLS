use util::hash::{sha256, sha512};
use cfg::settings::KeyEntropy;

const PADDING: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const C_KS: &'static str = "Signature & Encryption Keys";
const C_K: &'static str = "Encryption Key";
const C_S: &'static str = "Signature Key";

pub struct KeyPair {
    pub encryption: Vec<u8>,
    pub signature: Vec<u8>,
}

pub fn derive_key_pair(node: &[u8; 64], entropy: KeyEntropy) -> KeyPair {
    match entropy {
        KeyEntropy::Low => low_entropy_keys(node),
        KeyEntropy::Medium => med_entropy_keys(node),
        KeyEntropy::High => high_entropy_keys(node),
    }
}

fn low_entropy_keys(node: &[u8; 64]) -> KeyPair {
    let mut encryption_key = PADDING.clone().to_vec();
    let mut signature_key = PADDING.clone().to_vec();
    
    encryption_key.extend(&node[32..48]);
    signature_key.extend(&node[48..64]);
    
    KeyPair { encryption: encryption_key, signature: signature_key }
}

fn med_entropy_keys(node: &[u8; 64]) -> KeyPair {
    let mut concat = vec![];
    
    concat.extend(node.iter());
    concat.extend(C_KS.as_bytes().iter());
    
    let ks = sha512(concat.as_ref());
    
    KeyPair {
        encryption: ks[0..32].to_vec(),
        signature: ks[32..64].to_vec(),
    }
}

fn high_entropy_keys(node: &[u8; 64]) -> KeyPair {
    let mut pre_encryption_key = C_K.as_bytes().to_vec();
    let mut pre_signature_key = C_S.as_bytes().to_vec();
    
    pre_encryption_key.extend(node.iter());
    pre_signature_key.extend(node.iter());
    
    KeyPair {
        encryption: sha256(&pre_encryption_key[..]).to_vec(),
        signature: sha256(&pre_signature_key[..]).to_vec(),
    }
}
