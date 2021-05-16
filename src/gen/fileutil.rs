//! bpf-profile file utilities module.

use super::{Error, Result};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

/// Opens a file for reading.
pub fn open(filename: &Path) -> Result<impl Read> {
    let file = File::open(&filename).map_err(|e| Error::OpenFile(e, filename.into()))?;
    Ok(file)
}

/// Opens a file for writing; rewrites existing.
pub fn open_w(filename: &Path) -> Result<impl Write> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(&filename)
        .map_err(|e| Error::OpenFile(e, filename.into()))?;
    Ok(file)
}
