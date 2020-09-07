use std::collections::HashMap;

use chrono::{DateTime, Utc};

#[derive(Default, Debug)]
pub(super) struct Record {
    // `field:"09"`
    access_time: Option<DateTime<Utc>>,
    // `field:"0e"`
    autotype: String,
    // `field:"07"`
    create_time: Option<DateTime<Utc>>,
    // `field:"13"`
    double_click_action: [u8; 2],
    // `field:"14"`
    email: String,
    // `field:"02"`
    group: String,
    // DateTime does not implement Serialize
    // `field:"0c"`
    mod_time: Option<DateTime<Utc>>,
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
    // New Parses a set of records from the given data. As data is parsed out the mac is updated with
    // the string values of the records.
    pub(super) fn new(bytes: &[u8], mac: &mut crate::HmacSha256) -> Result<HashMap<String, Record>, String> {
        // TODO bytes should end with the END field type
        Err("not implemented".to_string())
    }
}
