extern crate siphasher;
extern crate time;
extern crate byteorder;
extern crate crypto;

use self::byteorder::{BigEndian, ReadBytesExt};
use self::crypto::md5::Md5;
use self::crypto::digest::Digest;
use self::time::PreciseTime;
use self::siphasher::sip::SipHasher13;
use bench::util::{NUM_TESTS, mean, std_dev};
use util::hash::HashChain;
use util::hash::sha512;
use std::io::Cursor;
use std::hash::Hasher;

pub fn run() -> Vec<(String, i64, i64)> {
    let load_factors: Vec<f32> = vec![0.70, 0.75, 0.80, 0.85, 0.90, 0.95];
    let entry_lens: Vec<usize> = vec![3, 22];
    let mut results: Vec<(String, i64, i64)> = vec![];
    
    load_factors.iter()
        .for_each(|load_factor| entry_lens.iter()
            .for_each(|entry_len| results.push(fill_to_load_factor(*load_factor, *entry_len))));
    
    results
}

fn fill_to_load_factor(load_factor: f32, entry_len: usize) -> (String, i64, i64) {
    let test_key = format!("fill_to_load_factor_{}_entry_len_{}", load_factor, entry_len);
    let mut bitmap = [true; 65536];
    let mut fill_count = 0 as usize;
    let mut chain = HashChain::new(&sha512(test_key.as_bytes()));
    let mut measurements = [0; NUM_TESTS];
    
    for i in 0..NUM_TESTS {
        let start = PreciseTime::now();
        
        while fill_count < (65536f32 * load_factor) as usize {
            let keys = keys_from_node(&chain.get_node());
            let mut hasher = SipHasher13::new_with_keys(keys.0, keys.1);
            
            for j in 0..entry_len {
                let i = compute_index(&bitmap, &mut hasher, j);
                
                bitmap[i] = false;
                fill_count += 1;
            }
            chain.evolve();
        }
        measurements[i] = start.to(PreciseTime::now()).num_nanoseconds().unwrap();
    }
    let mean = mean(&measurements);
    
    (test_key, mean, std_dev(&measurements, mean))
}

fn compute_index(bitmap: &[bool; 65536], hasher: &mut SipHasher13, start: usize) -> usize {
    let mut index = start;
    let mut res = index as u64;
    
    loop {
        let input = vec![
            res as u8,
            (res << 8) as u8,
            (res << 16) as u8,
            (res << 24) as u8,
            (res << 32) as u8,
            (res << 40) as u8,
            (res << 48) as u8,
            (res << 56) as u8,
        ];
        hasher.write(&input[..]);
        res = hasher.finish();
        index = (res as u16) as usize;
        
        if bitmap[index] { break; }
    }
    
    index
}

fn keys_from_node(node: &[u8; 64]) -> (u64, u64) {
    let mut hasher = Md5::new();
    let mut key_bytes = [0x00; 16];
    
    hasher.input(node);
    hasher.result(&mut key_bytes);
    
    let mut key1 = Cursor::new(key_bytes[0..8].to_vec());
    let mut key2 = Cursor::new(key_bytes[8..16].to_vec());
    
    (key1.read_u64::<BigEndian>().unwrap(), key2.read_u64::<BigEndian>().unwrap())
}
