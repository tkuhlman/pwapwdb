use std::collections::HashMap;

use chrono::{DateTime, Utc};

#[cfg(test)]
mod test;

// If this is in a crypto library that would be better than here
const SHA256_SIZE: usize = 32;

// TODO review naming conventions

// TODO review proper comment style
// Database is the decrypted password DB which can be queried for Record information
#[derive(Debug)]
pub struct Database {
    cbciv: [u8; 16],
    //Random initial value for CBC
    description: String,
    //   `field:"0a"`
    empty_groups: Vec<String>,
    // `field:"12"`
    encryption_key: [u8; 32],
    filters: String,
    //   `field:"0b"`
    hmac: [u8; 32],
    //32bytes keyed-hash MAC with SHA-256 as the hash function.
    hmac_key: [u8; 32],
    iter: u32,
    //the number of iterations on the hash function to create the stretched key
    last_mod: DateTime<Utc>,
    last_save: DateTime<Utc>,
    // `field:"04"`
    last_save_by: u8,
    // `field:"06"`
    last_save_host: u8,
    // `field:"08"`
    last_save_path: String,
    last_save_user: u8,
    // `field:"07"`
    name: String,
    // `field:"09"`
    password_policy: String,
    // `field:"10"`
    preferences: String,
    // `field:"02"`
    records: HashMap<String, Record>,
    //the key is the record title
    recenty_used: String,
    //        `field:"0f"`
    salt: [u8; 32],
    stretched_key: [u8; SHA256_SIZE],
    tree: String,
    // `field:"03"`
    uuid: [u8; 16],
    // `field:"01"`
    version: [u8; 2], // `field:"00"`
}

#[derive(Debug)]
struct Record {
    access_time: DateTime<Utc>,
    // `field:"09"`
    autotype: String,
    // `field:"0e"`
    create_time: DateTime<Utc>,
    // `field:"07"`
    double_click_action: [u8; 2],
    // `field:"13"`
    email: String,
    // `field:"14"`
    group: String,
    // `field:"02"`
    mod_time: DateTime<Utc>,
    // `field:"0c"`
    notes: String,
    // `field:"05"`
    password: String,
    // `field:"06"`
    password_expiry: DateTime<Utc>,
    // `field:"0a"`
    password_expiry_interval: [u8; 4],
    // `field:"11"`
    password_history: String,
    // `field:"0f"`
    password_mod_time: String,
    // `field:"08"`
    password_policy: String,
    // `field:"10"`
    password_policy_name: String,
    // `field:"18"`
    protected_entry: u8,
    // `field:"15"`
    run_command: String,
    // `field:"12"`
    shift_double_click_action: [u8; 2],
    // `field:"17"`
    title: String,
    // `field:"03"`
    username: String,
    // `field:"04"`
    url: String,
    // `field:"0d"`
    uuid: [u8; 16], // `field:"01"`
}

impl Database {
    // new creates a new database by reading from an encrypted data
    pub fn new(bytes: Vec<u8>, password: &str) -> Result<Database, &str> {
        if bytes.len() < 200 {
            return Err("DB data is less than minimum size");
        };

        match std::str::from_utf8(&bytes[0..4]) {
            Ok(tag) => if tag != "PWS3" { return Err("Data is not a Password Safe V3 DB"); },
            Err(_) => return Err("Data is not a Password Safe V3 DB"),
        };

        Err("Missing Data")
    }
}
