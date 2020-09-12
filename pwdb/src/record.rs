use std::collections::HashMap;

use chrono::{DateTime, Utc};
use hmac::Mac;

#[derive(Default, Debug)]
pub struct Record {
    pub access_time: Option<DateTime<Utc>>,
    autotype: String,
    pub create_time: Option<DateTime<Utc>>,
    credit_card_expiration: String,
    credit_card_number: String,
    credit_card_pin: String,
    credit_card_verify: String,
    double_click_action: [u8; 2],
    pub email: String,
    pub group: String,
    keyboard_shortcut: [u8; 4],
    pub mod_time: Option<DateTime<Utc>>,
    pub notes: String,
    pub password: String,
    password_expiry: u32,
    password_expiry_interval: [u8; 4],
    password_expiry_time: Option<DateTime<Utc>>,
    password_history: String,
    password_mod_time: Option<DateTime<Utc>>,
    password_policy: String,
    password_policy_name: String,
    password_symbols: String,
    protected_entry: u8,
    qr_code: String,
    run_command: String,
    shift_double_click_action: [u8; 2],
    pub title: String,
    two_factor_key: Vec<u8>,
    pub username: String,
    pub url: String,
    uuid: uuid::Uuid,
}

impl Record {
    // New Parses a set of records from the given data. As data is parsed out the mac is updated with
    // the string values of the records.
    pub(super) fn new_records(bytes: &[u8], mac: &mut crate::HmacSha256) -> Result<HashMap<uuid::Uuid, Record>, String> {
        let mut records: HashMap<uuid::Uuid, Record> = HashMap::new();
        let mut i: usize = 0;
        while i < bytes.len() {
            let (record, end) = Record::new(&bytes[i..], mac)?;
            records.insert(record.uuid, record);
            i += end;
        }
        Ok(records)
    }

    // new parses a single record from the given bytes returning the record and end position for that
    // record in the byte array
    fn new(bytes: &[u8], mac: &mut crate::HmacSha256) -> Result<(Record, usize), String> {
        let mut r = Record::default();
        let mut i: usize = 0;
        while i <= bytes.len() { // Generally the loop should break before this condition is hit
            let field = crate::Field::new(&bytes[i..])?;

            i += field.total_size;
            if i + 1 >= bytes.len() {
                if field.type_id != 0xff {
                    return Err("Final Header field is not expected end type".to_string())
                }
                break
            }

            match field.type_id {
                0x01 => r.uuid = uuid::Uuid::from_slice(&field.data).expect("Failed ot conver record UUID"),
                0x02 => r.group = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert group field to a string"),
                0x03 => r.title = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert title field to a string"),
                0x04 => r.username = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert username field to a string"),
                0x05 => r.notes = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert notes field to a string"),
                // TODO add support for password alias and shortcuts as defined in the spec
                0x06 => r.password = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert password field to a string"),
                0x07 => r.create_time = Some(crate::pwsafe_date(&field.data)?),
                0x08 => r.password_mod_time = Some(crate::pwsafe_date(&field.data)?),
                0x09 => r.access_time = Some(crate::pwsafe_date(&field.data)?),
                0x0a => r.password_expiry_time = Some(crate::pwsafe_date(&field.data)?),
                0x0b => continue,
                0x0c => r.mod_time = Some(crate::pwsafe_date(&field.data)?),
                0x0d => r.url = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert url field to a string"),
                0x0e => r.autotype = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert autotype field to a string"),
                0x0f => r.password_history = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert password history field to a string"),
                0x10 => r.password_policy = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert password policy field to a string"),
                0x11 => r.password_expiry_interval = crate::copy_into_array(&field.data[..4]),
                0x12 => r.run_command = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert run command field to a string"),
                0x13 => r.double_click_action = crate::copy_into_array(&field.data[..2]),
                0x14 => r.email = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert email field to a string"),
                0x15 => r.protected_entry = field.data[0],
                0x16 => r.password_symbols = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert password symbols field to a string"),
                0x17 => r.shift_double_click_action = crate::copy_into_array(&field.data[..2]),
                0x18 => r.password_policy_name = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert password policy name field to a string"),
                0x19 => r.keyboard_shortcut = crate::copy_into_array(&field.data[..4]),
                0x1a => continue,
                0x1b => r.two_factor_key = field.data.clone(),
                0x1c => r.credit_card_number = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert credit card number field to a string"),
                0x1d => r.credit_card_expiration = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert credit card expiration field to a string"),
                0x1e => r.credit_card_verify = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert credit card verify field to a string"),
                0x1f => r.credit_card_pin = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert credit card pin field to a string"),
                0x20 => r.qr_code = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert QR code field to a string"),
                0xff => break,
                _ => return Err(format!("Unknown record field type {}", field.type_id)),
            }

            // For every field except end add the data to the hmac
            mac.update(&field.data);
        }

        // Verify required fiedls
        if r.uuid.is_nil() {
            return Err("record is missing uuid".to_string())
        }
        if r.title == "" {
            return Err("record is missing title".to_string())
        }
        if r.password == "" {
            return Err(format!("record is missing password, title: '{}'", r.title))
        }
        Ok((r, i))
    }
}
