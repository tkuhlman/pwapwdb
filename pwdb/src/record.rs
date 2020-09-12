use std::collections::HashMap;

use chrono::{DateTime, Utc};
use hmac::Mac;

#[derive(Default, Debug)]
pub struct Record {
    pub access_time: Option<DateTime<Utc>>,
    autotype: String,
    pub create_time: Option<DateTime<Utc>>,
    double_click_action: [u8; 2],
    pub email: String,
    pub group: String,
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
    protected_entry: u8,
    run_command: String,
    shift_double_click_action: [u8; 2],
    pub title: String,
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
                // TODO add support for remaining fields
                _ => return Err("Unknown record field type".to_string()),
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
