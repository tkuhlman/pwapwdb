use std::collections::HashMap;
use std::str;

use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::NoPadding;
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;
use twofish::Twofish;

use header::*;
use preamble::*;
use record::*;

mod header;
mod preamble;
mod record;
#[cfg(test)]
mod test;

const EOF: &str = "PWS3-EOFPWS3-EOF";
// TODO If this is in a crypto library that would be better than here
const TWOFISH_BLOCK_SIZE: usize = 16;

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

        // Find the end of the encrypted section
        let mut pos = 152;
        while pos < bytes.len() {
            if pos + TWOFISH_BLOCK_SIZE > bytes.len() {
                return Err("Data size does not match expected size for twofish blocks".to_string())
            }
            if &bytes[pos..pos + TWOFISH_BLOCK_SIZE] == EOF.as_bytes() {
                break
            }
            pos += TWOFISH_BLOCK_SIZE;
        }
        if pos > bytes.len() {
            return Err("No EOF found in DB".to_string())
        }
        let hmac = &bytes[pos + TWOFISH_BLOCK_SIZE..];

        // Decrypt the primary block of data
        type TwoFishCbc = Cbc<Twofish, NoPadding>;
        // TODO don't panic if this unwraps a failure
        let cipher = TwoFishCbc::new_var(&preamble.stretched_key, &preamble.cbciv).unwrap();
        let result = cipher.decrypt_vec(&bytes[152..pos]);
        let data = match result {
            Ok(data) => data,
            Err(error) => return Err(error.to_string()),
        };

        // Verify the hmac is as expected, it is calculated only on the plain text fields in the
        // header and records, not the length/type fields
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_varkey(&preamble.hmac_key[..]).expect("Invalid hmac");

        let (header, header_hmac_data, data) = Header::new(&data)?;
        mac.update(&header_hmac_data);
        let last_mod = header.last_save;

        let (records, record_hmac_data) = Record::new(data)?;
        mac.update(&record_hmac_data);

        mac.verify(&hmac).expect("HMAC mismatch!");


        Ok(Database {
            preamble,
            header,
            last_mod,
            records,
        })
    }
}
