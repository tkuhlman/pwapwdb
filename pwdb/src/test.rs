use crate::*;

#[test]
fn new_empty_db() {
    let db = Database::new(&Vec::new(), "123");
    let msg = match db {
        Ok(_) => "success".to_string(),
        Err(error) => error,
    };
    assert_eq!(msg, "DB data is less than minimum size")
}

#[test]
fn new_invalid_data() {
    let db = Database::new(&(0..200).collect(), "123");
    let msg = match db {
        Ok(_) => "success".to_string(),
        Err(error) => error,
    };
    assert_eq!(msg, "Data is not a Password Safe V3 DB")
}

#[test]
fn wrong_passphrase() {
    let encrypted = include_bytes!("../test_dbs/simple.dat");

    let db = Database::new(&encrypted.to_vec(), "wrong");
    let msg = match db {
        Ok(_) => "success".to_string(),
        Err(error) => error,
    };
    assert_eq!(msg, "Invalid Password")
}

#[test]
fn bad_hmac() {
    let encrypted = include_bytes!("../test_dbs/badHMAC.dat");

    let db = Database::new(&encrypted.to_vec(), "password");
    let msg = match db {
        Ok(_) => "success".to_string(),
        Err(error) => error,
    };
    assert_eq!(msg, "HMAC mismatch!")
}

#[test]
fn decrypt_simple_db() {
    let encrypted = include_bytes!("../test_dbs/simple.dat");

    let db = Database::new(&encrypted.to_vec(), "password").unwrap();
    assert_eq!(db.records.len(), 1);
    let (_key, record) = db.records.iter().next().unwrap();
    assert_eq!(record.title, "Test entry");
    assert_eq!(record.username, "test");
    assert_eq!(record.password, "password");
    assert_eq!(record.group, "test");
    assert_eq!(record.url, "http://test.com");
    assert_eq!(record.notes, "no notes");
}

#[test]
fn decrypt_small_db() {
    let encrypted = include_bytes!("../test_dbs/three.dat");

    let db = Database::new(&encrypted.to_vec(), "three3#;").unwrap();
    assert_eq!(db.records.len(), 3);
    for (_, record) in db.records.iter() {
        match record.title.as_str() {
            "three entry 1" => {
                assert_eq!(record.username, "three1_user");
                assert_eq!(record.password, "three1!@$%^&*()");
                assert_eq!(record.group, "group1");
                assert_eq!(record.url, "http://group1.com");
                assert_eq!(record.notes, "three DB\r\nentry 1");
            },
            "three entry 2" => {
                assert_eq!(record.username, "three2_user");
                assert_eq!(record.password, "three2_-+=\\\\|][}{';:");
                assert_eq!(record.group, "group2");
                assert_eq!(record.url, "http://group2.com");
                assert_eq!(record.notes, "three DB\r\nsecond entry");
            },
            "three entry 3" => {
                assert_eq!(record.username, "three3_user");
                assert_eq!(record.password, ",./<>?`~0");
                assert_eq!(record.group, "group 3");
                assert_eq!(record.url, "https://group3.com");
                assert_eq!(record.notes, "three DB\r\nentry 3\r\nlast one");
            },
            _ => panic!("unknown record {}", record.title)
        }
    }
}

// TODO review test coverage