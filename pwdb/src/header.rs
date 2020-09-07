use chrono::{DateTime, NaiveDateTime, Utc};
use hmac::Mac;

#[derive(Default, Debug)]
pub(super) struct Header {
    description: String,
    empty_groups: String,
    filters: String,
    last_master_password_update: Option<DateTime<Utc>>,
    pub(super) last_save: Option<DateTime<Utc>>,
    last_save_by: String,
    last_save_host: String,
    last_save_user: String,
    name: String,
    password_policy: String,
    preferences: String,
    recently_used: String,
    tree_display_status: String,
    uuid: [u8; 16],
    version: [u8; 2],
    // little endian, see the format spec for details
    yubico: String,
}

impl Header {
    // Parse the header out of the given data return all bytes after the header end field.
    // As the data is parsed out the mac is updated with the string values of the records.
    pub(super) fn new(bytes: &[u8], mac: &mut crate::HmacSha256) -> Result<(Header, Vec<u8>), String> {
        let mut hdr = Header::default();
        let mut i = 0;
        while i <= bytes.len() { // Generally the loop should break before this condition is hit
            let field = crate::Field::new(&bytes[i..])?;
            /* The first field is supposed to be a version but isn't always
            if i == 0 && field.type_id != 0x00 {
                return Err("The first Header field is not a version field".to_string())
            }
            */

            i += field.total_size;
            if i + 1 >= bytes.len() {
                if field.type_id != 0xff {
                    return Err("Final Header field is not expected end type".to_string())
                }
                break
            }

            match field.type_id {
                0x00 => hdr.version = crate::copy_into_array(&*field.data),
                0x01 => {
                    if field.data.len() != 16 {
                        return Err("UUID field was not 16 bytes long".to_string())
                    }
                    hdr.uuid = crate::copy_into_array(&field.data);
                },
                0x02 => hdr.preferences = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert preferences to a string"),
                0x03 => hdr.tree_display_status = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert tree display status to a string"),
                0x04 => {
                    if field.data.len() != 4 {
                        return Err("Unexpected field length for last save date".to_string())
                    }
                    hdr.last_save = Some(DateTime::from_utc(
                        NaiveDateTime::from_timestamp(
                            u32::from_le_bytes(crate::copy_into_array(&field.data)) as i64, 0,
                        ), Utc));
                },
                0x05 => continue, // deprecated field, just drop it
                0x06 => hdr.last_save_by = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert last save by field to a string"),
                0x07 => hdr.last_save_user = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert last save user field to a string"),
                0x08 => hdr.last_save_host = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert last save host field to a string"),
                0x09 => hdr.name = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert DB name field to a string"),
                0x0a => hdr.description = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert description field to a string"),
                0x0b => hdr.filters = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert filters field to a string"),
                0x0f => hdr.recently_used = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert recently used field to a string"),
                0x10 => hdr.password_policy = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert password policy field to a string"),
                0x11 => hdr.empty_groups = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert empty groups field to a string"),
                0x12 => hdr.yubico = String::from_utf8(
                    field.data.clone()
                ).expect("Failed to convert yubico field to a string"),
                0x13 => {
                    if field.data.len() != 4 {
                        return Err("Unexpected field length for last master password update".to_string())
                    }
                    hdr.last_save = Some(DateTime::from_utc(
                        NaiveDateTime::from_timestamp(
                            u32::from_le_bytes(crate::copy_into_array(&field.data)) as i64, 0,
                        ), Utc));
                },
                0xff => break,
                _ => return Err("Unknown header field type".to_string()),
            }

            // For every field except end add the data to the hmac
            mac.update(&field.data);
        }

        Ok((hdr, bytes[i..].to_owned()))
    }
}