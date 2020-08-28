use std::collections::HashMap;

use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::NoPadding;
use twofish::Twofish;

use header::*;
use preamble::*;
use record::*;

mod header;
mod preamble;
mod record;
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

        let header = Header::new(data)?;
        // TODO Header::new needs to return record data so it can be parsed below by record::new
        let records = Record::new(Vec::from(&bytes[0..152]))?;
        let last_mod = header.last_save;

        Ok(Database {
            preamble,
            header,
            last_mod,
            records,
        })
    }
}
