pub mod exec {
    extern crate clap;
    
    use app::logger::Logger;
    use app::interpreter::Interpreter;
    use app::verifier::Verifier;
    use bench::*;
    use cfg::config::Config;
    use cfg::settings::{HmacAlgorithm, KeyEntropy};
    use clap::ArgMatches;
    use util::hash::HashChain;
    use util::key_derivation::derive_key_pair;
    use util::misc::root_from_str;
    use std::io::{BufRead, BufReader, Read, BufWriter, Write};
    use std::fs::{File, remove_file};
    use std::path::Path;
    
    pub fn encrypt_file(matches: &ArgMatches) -> Result<(), String> {
        let secrets = parse_secrets(matches)?;
        let config = parse_config(matches)?;
        let file_path = matches.value_of("INPUT").unwrap();
        let new_file_path = format!("{}_encrypted", file_path);
        let mut logger = Logger::new(config, new_file_path.as_ref(), &secrets.0, &secrets.1);
        let reader = match File::open(file_path) {
            Ok(file) => BufReader::new(file),
            Err(ref e) => return Err(format!("{}", e))
        };
        let mut results: Vec<Result<(), String>> = vec![];
        
        reader.lines()
            .enumerate()
            .map(|(i, msg)| (i + 1, msg))
            .for_each(|(i, msg)|
                {
                    if msg.is_err() {
                        results.push(Err(format!("An error occurred trying to read line {}.", i)))
                    } else if logger.log(&msg.unwrap()).is_err() {
                        results.push(Err(format!("An error occurred trying to log line {}.", i)))
                    }
                    results.push(Ok(()));
                });
        
        if results.iter().all(|res| res.is_ok()) { return Ok(()); } else {
            return Err(
                results.iter()
                    .filter(|res| res.is_err())
                    .fold(
                        String::from(""),
                        |p, err| format!("{}\n{}", p, err.as_ref().unwrap_err())
                    )
            );
        }
    }
    
    pub fn decrypt_file(matches: &ArgMatches) -> Result<(), String> {
        let file_path = matches.value_of("INPUT").unwrap().to_string();
        let new_file_path = format!("{}_decrypted", file_path);
        let mut interpreter = Interpreter::new(file_path.as_ref());
        let keys = get_keys(matches.value_of("keys").unwrap())?;
        let keys_borrowed: Vec<&Vec<u8>> = keys.iter().map(|key| key).collect();
        let mut writer = match File::create(&new_file_path) {
            Ok(file) => BufWriter::new(file),
            Err(ref e) => return Err(format!("{}: {}", new_file_path, e))
        };
        let mut results: Vec<Result<(), String>> = vec![];
        
        interpreter.get_plaintexts(&keys_borrowed)
            .iter()
            .enumerate()
            .map(|(i, res)| (i + 1, res))
            .for_each(|(i, res)| {
                results.push(match *res {
                    Ok(ref line) => match writer.write_all(format!("{}\n", line).as_bytes()) {
                        Ok(_) => Ok(()),
                        Err(ref e) => Err(format!("{}", e))
                    },
                    Err(_) => Err(format!("An error occurred trying to decrypt line {}.", i))
                })
            });
        
        if results.iter().all(|res| res.is_ok()) { return Ok(()); } else {
            return Err(
                results.iter()
                    .filter(|res| res.is_err())
                    .fold(
                        String::from(""),
                        |p, err| format!("{}\n{}", p, err.as_ref().unwrap_err())
                    )
            );
        }
    }
    
    pub fn verify_file(matches: &ArgMatches) -> Result<(), String> {
        let file_path = matches.value_of("INPUT").unwrap();
        let verifier = Verifier::new(file_path);
        let keys = get_keys(matches.value_of("keys").unwrap())?;
        let mut keys_borrowed: Vec<&Vec<u8>> = keys.iter().map(|key| key).collect();
        let first_decryption_key = keys_borrowed.remove(0);
        let secret = matches.value_of("secret").unwrap().to_string();
        
        match verifier.verify(&secret, &keys_borrowed, first_decryption_key) {
            Ok(_) => Ok(()),
            Err(ref e) => return Err(format!("{}", e))
        }
    }
    
    fn get_keys(path: &str) -> Result<Vec<Vec<u8>>, String> {
        if !Path::new(path).exists() {
            return Err(String::from("The specified key file does not exist."));
        }
        let file = match File::open(path) {
            Ok(file) => file,
            Err(ref e) => return Err(format!("{}", e))
        };
        let num_keys = match File::open(path).unwrap().metadata() {
            Ok(data) => data.len() / 32,
            Err(ref e) => return Err(format!("{}", e))
        };
        let mut reader = BufReader::new(file);
        let mut keys: Vec<Vec<u8>> = vec![];
        
        for _ in 0..num_keys {
            let mut key = [0xff; 32];
            
            match reader.read(&mut key) {
                Ok(_) => (),
                Err(ref e) => return Err(format!("{}", e))
            }
            keys.push(key.to_vec())
        }
        
        Ok(keys)
    }
    
    pub fn generate_keys(matches: &ArgMatches) -> Result<(), String> {
        let root = parse_root(matches, "INPUT")?;
        let amount: usize = match matches.value_of("amount").unwrap().parse() {
            Ok(n) => n,
            Err(_) => return Err(String::from("Specified value for `amount` was not a number."))
        };
        let key_entropy = parse_key_entropy(matches)?;
        let key_type = match matches.value_of("type").unwrap_or("both") {
            "signature" => "signature",
            "encryption" => "encryption",
            "both" => "both",
            _ => return Err(String::from(
                "Specified value for `type` was not both, signature or encryption")
            )
        };
        let mut chain = HashChain::new(&root);
        let mut encryption_key_file: BufWriter<File> = match File::create("encryption.keys") {
            Ok(file) => BufWriter::new(file),
            Err(e) => return Err(format!("{}", e))
        };
        let mut signature_key_file: BufWriter<File> = match File::create("signature.keys") {
            Ok(file) => BufWriter::new(file),
            Err(e) => return Err(format!("{}", e))
        };
        if key_type == "signature" { remove_file("encryption.keys").unwrap() }
        if key_type == "encryption" { remove_file("signature.keys").unwrap() }
        
        for i in 0..amount {
            let keys = derive_key_pair(&chain.get_node(), key_entropy);
            
            if key_type == "signature" || key_type == "both" {
                if i == 0 {
                    match signature_key_file.write_all(&keys.encryption[..]) {
                        Ok(_) => (),
                        Err(ref e) => return Err(format!("{}", e))
                    }
                }
                match signature_key_file.write_all(&keys.signature[..]) {
                    Ok(_) => (),
                    Err(ref e) => return Err(format!("{}", e))
                }
            }
            if (key_type == "encryption" || key_type == "both") && i > 0 {
                match encryption_key_file.write_all(&keys.encryption[..]) {
                    Ok(_) => (),
                    Err(ref e) => return Err(format!("{}", e))
                }
            }
            chain.evolve();
        }
        
        Ok(())
    }
    
    pub fn benchmark() {
        println!("LOGGER");
        logger_benchmark::run()
            .iter()
            .for_each(|res| println!("{},{},{}", res.0, res.1, res.2));
        
        println!("INTERPRETER");
        interpreter_benchmark::run()
            .iter()
            .for_each(|res| println!("{},{},{}", res.0, res.1, res.2));
        
        println!("VERIFIER");
        verifier_benchmark::run()
            .iter()
            .for_each(|res| println!("{},{},{}", res.0, res.1, res.2));
    }
    
    fn parse_root(matches: &ArgMatches, arg_name: &str) -> Result<[u8; 64], String> {
        let root_str = matches.value_of(arg_name).unwrap();
        
        match root_str.len() {
            64 => Ok(root_from_str(&String::from(root_str))),
            _ => return Err(String::from("The chain root should be exactly 64 bytes in length."))
        }
    }
    
    fn parse_key_entropy(matches: &ArgMatches) -> Result<KeyEntropy, String> {
        match matches.value_of("key_entropy").unwrap_or("med") {
            "high" | "hi" => Ok(KeyEntropy::High),
            "medium" | "med" => Ok(KeyEntropy::Medium),
            "low" | "lo" => Ok(KeyEntropy::Low),
            _ => Err(String::from("Specified value for `key_entropy` was not low, medium or high."))
        }
    }
    
    fn parse_secrets(matches: &ArgMatches) -> Result<(String, [u8; 64]), String> {
        let secret = matches.value_of("secret").unwrap().to_string();
        let root = parse_root(matches, "root")?;
        
        Ok((secret, root))
    }
    
    fn parse_config(matches: &ArgMatches) -> Result<Config, String> {
        let cipher_block_len: u8 = if matches.value_of("cipher_block_len").is_none() { 6 } else {
            match matches.value_of("cipher_block_len").unwrap().parse() {
                Ok(len) => len,
                Err(_) => return Err(
                    String::from("Invalid value specified for `cipher_block_len`.")
                )
            }
        };
        let key_entropy = parse_key_entropy(matches)?;
        let hmac_alg = match matches.value_of("hmac_alg").unwrap_or("SHA256") {
            "SHA512" | "sha512" => HmacAlgorithm::HmacSha512,
            "SHA256" | "sha256" => HmacAlgorithm::HmacSha256,
            _ => return Err(String::from("Specified value for `hmac_alg` was not SHA512, or SHA256"))
        };
        
        Ok(Config::new(cipher_block_len, key_entropy, hmac_alg))
    }
    
    #[cfg(test)]
    mod tests {
        #[test]
        fn is_ok() {}
    }
}
