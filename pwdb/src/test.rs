use crate::*;

#[test]
fn new_empty_db() {
    let db = Database::new(Vec::new(), "123");
    let msg = match db {
        Ok(_) => "succes",
        Err(error) => error,
    };
    assert_eq!(msg, "DB data is less than minimum size")
}

#[test]
fn new_invalid_data() {
    let db = Database::new((0..200).collect(), "123");
    let msg = match db {
        Ok(_) => "succes",
        Err(error) => error,
    };
    assert_eq!(msg, "Data is not a Password Safe V3 DB")
}

// TODO get some test DBs and read with
// use std:fs;
// fs::read()