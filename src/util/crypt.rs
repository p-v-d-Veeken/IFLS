extern crate crypto;

use self::crypto::symmetriccipher::SymmetricCipherError;
use self::crypto::blockmodes::PkcsPadding;
use self::crypto::aes::{cbc_encryptor, cbc_decryptor, KeySize};
use self::crypto::buffer::*;

const IV: [u8; 16] = [0xff; 16];

pub fn encrypt(m: &String, key: &Vec<u8>) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut encryptor = cbc_encryptor(KeySize::KeySize256, &key[..], &IV, PkcsPadding);
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = RefReadBuffer::new(m.as_bytes());
    let mut buffer = [0; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);
    
    loop {
        let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;
        
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }
    
    Ok(final_result)
}

pub fn decrypt(c: &Vec<u8>, key: &Vec<u8>) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut decryptor = cbc_decryptor(KeySize::KeySize256, &key[..], &IV, PkcsPadding);
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = RefReadBuffer::new(&c);
    let mut buffer = [0; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);
    
    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
        
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }
    
    Ok(final_result)
}
