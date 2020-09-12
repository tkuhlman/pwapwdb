use crate::*;

#[test]
fn new_empty_db() {
    let db = Database::new(Vec::new(), "123");
    let msg = match db {
        Ok(_) => "success".to_string(),
        Err(error) => error,
    };
    assert_eq!(msg, "DB data is less than minimum size")
}

#[test]
fn new_invalid_data() {
    let db = Database::new((0..200).collect(), "123");
    let msg = match db {
        Ok(_) => "success".to_string(),
        Err(error) => error,
    };
    assert_eq!(msg, "Data is not a Password Safe V3 DB")
}

#[test]
fn wrong_passphrase() {
    let encrypted = include_bytes!("../test_dbs/simple.dat");

    let db = Database::new(encrypted.to_vec(), "wrong");
    let msg = match db {
        Ok(_) => "success".to_string(),
        Err(error) => error,
    };
    assert_eq!(msg, "Invalid Password")
}

#[test]
fn decrypt_simple_db() -> Result<(), String> {
    let encrypted = include_bytes!("../test_dbs/simple.dat");

    let db = Database::new(encrypted.to_vec(), "password")?;
    assert_eq!(db.records.len(), 1);
    let (_key, record) = db.records.iter().next().unwrap();
    assert_eq!(record.title, "Test entry");
    Ok(())
}

// TODO test with additional test DBs

// TODO review test coverage
