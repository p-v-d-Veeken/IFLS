use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::{Error, SeekFrom};
use cfg::config::{Config, HEADER_BYTE_LEN, ENTRY_MAX_BYTE_SIZE};
use log::log_entry::LogEntry;

pub struct LogFile {
    pub config: Config,
    file: File,
    count: usize,
    read_ptr: u64,
}

impl LogFile {
    pub fn new(config: Config, path_str: &str) -> LogFile {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(path_str)
            .expect("Could not create log file.");
        let mut log_file = LogFile { config, file, count: 0, read_ptr: 0 as u64 };
        
        log_file.write_config();
        
        log_file
    }
    
    pub fn open(path_str: &str) -> LogFile {
        let mut file = File::open(path_str).expect("Could not open log file.");
        let config = LogFile::read_config(&mut file);
        let size = file.metadata().expect("Could not get file metadata").len();
        let count = ((size - HEADER_BYTE_LEN as u64) / (config.entry_byte_size() as u64)) as usize;
        
        LogFile { config, file, count, read_ptr: HEADER_BYTE_LEN as u64 }
    }
    
    pub fn write_log_entry(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
        if self.count > 0 {
            self.file.seek(SeekFrom::End(-(self.config.sign_byte_size() as i64)))?;
        }
        self.file.write(&bytes[..])?;
        self.count += 1;
        
        Ok(())
    }
    
    pub fn entry_count(&self) -> usize { self.count }
    
    pub fn is_empty(&self) -> bool { self.entry_count() == 0 }
    
    pub fn peek(&mut self) -> Option<LogEntry> {
        let entry = self.next();
        
        if entry.is_some() { self.read_ptr -= self.config.entry_byte_size() as u64 }
        
        return entry;
    }
    
    fn read_config(file: &mut File) -> Config {
        file.seek(SeekFrom::Start(0)).expect("Could not seek to the beginning of the log file.");
        
        let mut bytes = [0u8; HEADER_BYTE_LEN];
        
        file.read(&mut bytes).expect("Could not read config header from log file.");
        
        Config::from_bytes(bytes)
    }
    
    fn write_config(&mut self) {
        self.file.seek(SeekFrom::Start(0)).expect("Could not seek to the beginning of log file.");
        
        let bytes = self.config.to_bytes();
        
        self.file.write(&bytes).expect("Could not write header config to new log file.");
        self.read_ptr += HEADER_BYTE_LEN as u64;
    }
}

impl Iterator for LogFile {
    type Item = LogEntry;
    
    fn next(&mut self) -> Option<Self::Item> {
        if self.read_ptr as usize >= self.count * self.config.entry_byte_size() {
            return None;
        }
        self.file.seek(SeekFrom::Start(self.read_ptr)).expect("Could not seek to next log entry.");
        
        let mut bytes = [0u8; ENTRY_MAX_BYTE_SIZE];
        
        self.file.read(&mut bytes).expect("Could not read bytes from log file.");
        self.read_ptr += self.config.entry_byte_size() as u64;
        
        let entry = LogEntry::from_bytes(
            bytes.to_vec(),
            &self.config,
        );
        
        Some(entry)
    }
}
