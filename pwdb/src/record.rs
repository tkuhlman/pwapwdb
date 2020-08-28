use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub(super) struct Record {
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

impl Record {
    // TODO It would be an interesting learning exercise to implment a serde deserializer for this, see
    // https://serde.rs/impl-deserializer.html
    pub(super) fn new(bytes: Vec<u8>) -> Result<HashMap<String, Record>, String> {
        Err("not implemented".to_string())
    }
}
