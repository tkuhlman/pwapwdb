use std::collections::HashMap;
use std::convert::AsMut;

use chrono::{DateTime, Utc};
use generic_array::GenericArray;
use sha2::{Digest, Sha256};
use twofish::block_cipher::{BlockCipher, NewBlockCipher};
use twofish::Twofish;

#[cfg(test)]
mod test;

// TODO If this is in a crypto library that would be better than here
// I see a blocksize trait I may be able to use
const SHA256_SIZE: usize = 32;

// TODO review naming conventions
// TODO review code structure, should I move some of this stuff to other files
// TODO review proper comment style
// Database is the decrypted password DB which can be queried for Record information
#[derive(Debug)]
pub struct Database {
    preamble: Preamble,
    //Random initial value for CBC
    description: String,
    //   `field:"0a"`
    empty_groups: Vec<String>,
    // `field:"12"`
    filters: String,
    //   `field:"0b"`
    hmac: [u8; 32],
    //32bytes keyed-hash MAC with SHA-256 as the hash function.
    last_mod: u32,
    // Timestamps are stored as 32 bit, little endian, unsigned integers,
    //  representing the number of seconds since Midnight, January 1, 1970, GMT
    last_save: u32,
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
    pub fn new(bytes: Vec<u8>, password: &str) -> Result<Database, String> {
        if bytes.len() < 200 {
            return Err("DB data is less than minimum size".to_string());
        };

        let preamble = Preamble::new(Vec::from(&bytes[0..152]), password)?;

        // TODO decrypt
        // &bytes[152..bytes.len()] are all encrypted with twofish in CBC mode
        /*
        Database{
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
        }
         */
        Err("Missing Data".to_string())
    }
}

// preamble is all the fields in the Password Safe V3 format which are not part of the encrypted block.
#[derive(Debug)]
struct Preamble {
    cbciv: [u8; 16],
    encryption_key: [u8; 32],
    hmac_key: [u8; 32],
    iter: u32,
    //the number of iterations on the hash function to create the stretched key
    salt: [u8; 32],
    stretched_key: [u8; SHA256_SIZE],
}

impl Preamble {
    // new extracts the preamble fields from the given bytes. As part of this it does initial password verification.
    fn new(bytes: Vec<u8>, password: &str) -> Result<Preamble, String> {
        if bytes.len() != 152 {
            return Err("Expected a preamble to be exactly 152 bytes".to_string());
        }
        match std::str::from_utf8(&bytes[0..4]) {
            Ok(tag) => if tag != "PWS3" { return Err("Data is not a Password Safe V3 DB".to_string()); },
            Err(_) => return Err("Data is not a Password Safe V3 DB".to_string()),
        };

        let key_hash = &bytes[40..72];
        let salt: [u8; 32] = copy_into_array(&bytes[4..36]);
        let iter = u32::from_le_bytes(copy_into_array(&bytes[36..40]));
        let cbciv: [u8; 16] = copy_into_array(&bytes[136..152]);

        let stretched_key = calculate_stretch_key(password, iter, salt);
        if key_hash[..] != Sha256::digest(&stretched_key[..])[..] {
            return Err("Invalid Password".to_string());
        }

        let keys = extract_keys(&bytes[72..136], &stretched_key);

        Ok(Preamble {
            cbciv,
            encryption_key: keys.0,
            hmac_key: keys.1,
            iter,
            salt,
            stretched_key,
        })
    }
}

fn calculate_stretch_key(password: &str, iterations: u32, salt: [u8; 32]) -> [u8; SHA256_SIZE] {
    let salted = [password.as_bytes(), &salt].concat();
    let mut stretched = Sha256::digest(&salted);
    for _ in 0..iterations {
        stretched = Sha256::digest(&stretched[..]);
    }
    stretched.into()
}

fn extract_keys(data: &[u8], stretched_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // TODO don't panic if this unwraps a failure
    let cipher = Twofish::new_varkey(stretched_key).unwrap();

    let mut encryption_key = [0u8; 32];
    encryption_key[..32].copy_from_slice(&data[0..32]);
    let mut hmac_key = [0u8; 32];
    hmac_key[..32].copy_from_slice(&data[32..64]);
    cipher.decrypt_block(GenericArray::from_mut_slice(&mut encryption_key));
    cipher.decrypt_block(GenericArray::from_mut_slice(&mut hmac_key));
    (encryption_key, hmac_key)
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