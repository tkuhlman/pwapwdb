use std::collections::HashMap;
use std::path::Path;
use std::str;
use std::time;

use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::NoPadding;
use chrono::{DateTime, Utc};
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

type HmacSha256 = Hmac<Sha256>;

// TODO review naming conventions
// TODO review proper comment style
// Database is the decrypted password DB which can be queried for Record information
#[derive(Debug)]
pub struct Database {
    // The preamble is the non-encrypted data in the DB file
    preamble: Preamble,
    header: Header,
    // Last update to the DB records, independent than the last save timestamp in the header
    last_mod: DateTime<Utc>,
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
        let cipher = TwoFishCbc::new_var(&preamble.encryption_key, &preamble.cbciv).unwrap();
        let result = cipher.decrypt_vec(&bytes[152..pos]);
        let data = match result {
            Ok(data) => data,
            Err(error) => return Err(error.to_string()),
        };

        // Verify the hmac is as expected, it is calculated only on the plain text fields in the
        // header and records, not the length/type fields
        let mut mac = HmacSha256::new_varkey(&preamble.hmac_key[..]).expect("Invalid hmac");

        let (header, data) = Header::new(&data, &mut mac)?;
        let mut last_mod = DateTime::<Utc>::from(time::SystemTime::now());
        if let Some(save_date) = header.last_save {
            last_mod = save_date;
        }

        let records = Record::new(&data, &mut mac)?;

        mac.verify(&hmac).expect("HMAC mismatch!");

        Ok(Database {
            preamble,
            header,
            last_mod,
            records,
        })
    }
}

// Field represents a header or record field used in the database.
struct Field {
    total_size: usize,
    // this is a multiplier of the block size
    type_id: u8,
    data: Vec<u8>,
}

impl Field {
    // new parses a field from the given bytes assuming a Twofish block size
    fn new(bytes: &[u8]) -> Result<Field, String> {
        let size = u32::from_le_bytes(copy_into_array(&bytes[..4])) as usize;
        let mut total_size = 5 + size;
        let remainder = total_size % TWOFISH_BLOCK_SIZE;
        if remainder != 0 {
            total_size += TWOFISH_BLOCK_SIZE - remainder;
        }

        if total_size > bytes.len() + 1 {
            return Err(format!("Data length of field {} is larger than the byte slice length {}", total_size, bytes.len()))
        }

        Ok(Field {
            data: bytes[5..5 + size].to_vec(),
            total_size,
            type_id: bytes[4],
        })
    }
}

// TODO make sure I understand this and try out the try_into variants
// Also make it so that returns an error rather than panic on failure
// this code was copied from https://stackoverflow.com/questions/25428920/how-to-get-a-slice-as-an-array-in-rust
fn copy_into_array<A, T>(slice: &[T]) -> A
    where
        A: Default + AsMut<[T]>,
        T: Copy,
{
    let mut a = A::default();
    <A as AsMut<[T]>>::as_mut(&mut a).copy_from_slice(slice);
    a
}
