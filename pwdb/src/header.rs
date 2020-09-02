use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub(super) struct Header {
    // `field:"0a"`
    description: String,
    // `field:"12"`
    empty_groups: Vec<String>,
    //   `field:"0b"`
    filters: String,
    // `field:"04"`
    // Timestamps are stored as 32 bit, little endian, unsigned integers,
    //  representing the number of seconds since Midnight, January 1, 1970, GMT
    pub(super) last_save: u32,
    // `field:"06"`
    last_save_by: u8,
    // `field:"08"`
    last_save_host: u8,
    // `field:"07"`
    last_save_user: u8,
    // `field:"09"`
    name: String,
    // `field:"10"`
    password_policy: String,
    // `field:"02"`
    preferences: String,
    //        `field:"0f"`
    recenty_used: String,
    // `field:"03"`
    tree: String,
    // `field:"01"`
    uuid: [u8; 16],
    version: [u8; 2], // `field:"00"`
}

impl Header {
    // Parse the header out of the given data return all bytes after the header end field
    pub(super) fn new(bytes: &[u8]) -> Result<(Header, Vec<u8>, Vec<u8>), String> {
        Err("not implemented".to_string())
    }
}