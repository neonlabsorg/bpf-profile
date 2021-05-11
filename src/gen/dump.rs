//! bpf_profile dump module.

use super::{Error, Result};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;
//use tracing::info;

/// Reads the dump file (if any) and returns a dump representation.
pub fn read(filename: Option<PathBuf>) -> Result<Object> {
    match filename {
        None => Ok(Object::default()),
        Some(filename) => {
            let file = File::open(&filename).map_err(|e| Error::OpenFile(e, filename))?;
            Object::read(BufReader::new(file))
        }
    }
}

/// Represents the dumpfile contents.
#[derive(Default)]
pub struct Object {}

impl Object {
    /// Returns new instance of the dump object.
    fn read(_file: impl Read) -> Result<Self> {
        Ok(Object {})
    }
}
