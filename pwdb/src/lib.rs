use std::collections::HashMap;

use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::NoPadding;
use serde::{Deserialize, Serialize};
use twofish::Twofish;

use header::*;
use preamble::*;

mod header;
mod preamble;
#[cfg(test)]
mod test;

// TODO review naming conventions
// TODO review proper comment style
// Database is the decrypted password DB which can be queried for Record information
#[derive(Debug)]
pub struct Database {
    // The preamble is the non-encrypted data in the DB file
    preamble: Preamble,
    header: Header,
    // Last update to the DB records, independent than the last save timestamp in the header
    last_mod: u32,
    //the key is the record title
    records: HashMap<String, Record>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Record {
    // TODO investigate DateTime serialization, https://serde.rs/custom-date-format.html
    // access_time: DateTime<Utc>, DateTime does not implement Serialize
    // `field:"09"`
    access_time: u32,
    // `field:"0e"`
    autotype: String,
    // DateTime does not implement Serialize
    // `field:"07"`
    create_time: u32,
    // `field:"13"`
    double_click_action: [u8; 2],
    // `field:"14"`
    email: String,
    // `field:"02"`
    group: String,
    // DateTime does not implement Serialize
    // `field:"0c"`
    mod_time: u32,
    // `field:"05"`
    notes: String,
    // `field:"06"`
    password: String,
    // DateTime does not implement Serialize
    // `field:"0a"`
    password_expiry: u32,
    // `field:"11"`
    password_expiry_interval: [u8; 4],
    // `field:"0f"`
    password_history: String,
    // `field:"08"`
    password_mod_time: String,
    // `field:"10"`
    password_policy: String,
    // `field:"18"`
    password_policy_name: String,
    // `field:"15"`
    protected_entry: u8,
    // `field:"12"`
    run_command: String,
    // `field:"17"`
    shift_double_click_action: [u8; 2],
    // `field:"03"`
    title: String,
    // `field:"04"`
    username: String,
    // `field:"0d"`
    url: String,
    uuid: [u8; 16], // `field:"01"`
}

impl Database {
    // TODO consider switching to std::error::Error rather than a string for the Err result
    // new creates a new database by reading from an encrypted data
    pub fn new(bytes: Vec<u8>, password: &str) -> Result<Database, String> {
        if bytes.len() < 200 {
            return Err("DB data is less than minimum size".to_string());
        };

        let preamble = Preamble::new(Vec::from(&bytes[0..152]), password)?;

        // Decrypt the primary block of data
        // TODO don't panic if this unwraps a failure
        type TwoFishCbc = Cbc<Twofish, NoPadding>;
        let cipher = TwoFishCbc::new_var(&preamble.stretched_key, &preamble.cbciv).unwrap();
        let result = cipher.decrypt_vec(&bytes[152..]);
        let data = match result {
            Ok(data) => data,
            Err(error) => return Err(error.to_string()),
        };

        // TODO validate the EOF, should be "PWS3-EOFPWS3-EOF" right before the HMAC and after the records
        // TODO pull the HMAC (final 256 bits) and compare to a calculated HMAC which is a key hashed MAC using SHA-256 over all unecncrypted data from the start of the header to the EOF

        // TODO use serde to deserialize the Header then the records and add to the DB

        Err("not fully implemented".to_string())
        /*
               Ok(Database{
                   preamble,
                   description: "".to_string(),
                   empty_groups: vec![],
                   filters: "".to_string(),
                   hmac: [u8;32].default(),
                   last_mod: 0,
                   last_save: 0,
                   last_save_by: 0,
                   last_save_host: 0,
                   last_save_path: "".to_string(),
                   last_save_user: 0,
                   name: "".to_string(),
                   password_policy: "".to_string(),
                   preferences: "".to_string(),
                   records: (HashMap<String, Record>).default(),
                   recenty_used: "".to_string(),
                   tree: "".to_string(),
                   uuid: [u8; 16].default(),
                   version: [u8; 2].default(),
               })

        */
    }
}
