use cfg::config::Config;

pub const NUM_TESTS: usize = 100;

pub struct Cfgs {
    pub v: Vec<(&'static str, Config)>
}

impl Cfgs {
    pub fn new(block_len: u8) -> Cfgs {
        let mut v = vec![];
        
        v.push(("low_sha256", Config::from_bytes([block_len, 0, 0])));
        v.push(("med_sha256", Config::from_bytes([block_len, 1, 0])));
        v.push(("high_sha256", Config::from_bytes([block_len, 2, 0])));
        v.push(("low_sha512", Config::from_bytes([block_len, 0, 1])));
        v.push(("med_sha512", Config::from_bytes([block_len, 1, 1])));
        v.push(("high_sha512", Config::from_bytes([block_len, 2, 1])));
        
        Cfgs { v }
    }
}

pub fn mean(measurements: &[i64; NUM_TESTS]) -> i64 {
    let sum: i64 = measurements.iter().sum();
    
    sum / (NUM_TESTS as i64)
}

pub fn std_dev(measurements: &[i64; NUM_TESTS], mean: i64) -> i64 {
    let squared_diff_sum: i64 = measurements.iter()
        .map(|v| {
            let diff = if mean > *v { mean - *v } else { *v - mean };
            
            diff * diff
        })
        .sum();
    let var: f64 = (squared_diff_sum / (NUM_TESTS as i64)) as f64;
    
    var.sqrt() as i64
}
