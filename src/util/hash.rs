extern crate crypto;

use cfg::settings::HmacAlgorithm;
use self::crypto::digest::Digest;
use self::crypto::hmac::Hmac;
use self::crypto::mac::Mac;
use self::crypto::sha2::{Sha256, Sha512};

pub fn hmac(data: &Vec<u8>, key: &Vec<u8>, alg: HmacAlgorithm) -> Vec<u8> {
    match alg {
        HmacAlgorithm::HmacSha512 => hmac_sha512(data, key).to_vec(),
        HmacAlgorithm::HmacSha256 => hmac_sha256(data, key).to_vec(),
    }
}

pub fn sha512(digest: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    let mut output = [0xff; 64];
    hasher.input(digest);
    hasher.result(&mut output);
    
    output
}

pub fn hmac_sha512(data: &Vec<u8>, key: &Vec<u8>) -> [u8; 64] {
    let mut hmac = Hmac::new(Sha512::new(), &key[..]);
    let mut result = [0xff; 64];
    
    hmac.input(&data[..]);
    hmac.raw_result(&mut result);
    
    result
}

pub fn sha256(digest: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let mut output = [0xff; 32];
    hasher.input(digest);
    hasher.result(&mut output);
    
    output
}

pub fn sha256_trunc_128(digest: &[u8]) -> [u8; 16] {
    let digest = sha256(digest);
    let mut digest_trunc: [u8; 16] = [0x11; 16];
    
    digest.iter()
        .take(16)
        .enumerate()
        .for_each(|(i, b)| digest_trunc[i] = *b);
    
    digest_trunc
}

pub fn hmac_sha256(data: &Vec<u8>, key: &Vec<u8>) -> [u8; 32] {
    let mut hmac = Hmac::new(Sha256::new(), &key[..]);
    let mut result = [0xff; 32];
    
    hmac.input(&data[..]);
    hmac.raw_result(&mut result);
    
    result
}

#[derive(Copy)]
pub struct HashChain {
    node: [u8; 64],
}

impl HashChain {
    pub fn new(root: &[u8; 64]) -> HashChain {
        HashChain { node: *root }
    }
    
    pub fn evolve(&mut self) { self.node = sha512(&self.node) }
    
    pub fn get_node(self) -> [u8; 64] { self.node }
}

impl Clone for HashChain {
    fn clone(&self) -> HashChain {
        HashChain { node: self.node }
    }
}
