//! bpf-profile output module.

use super::{Error, Result};
use std::io::Write;
use std::path::PathBuf;

/// Opens output file for writing; rewrites existing.
pub fn open_w(filename: PathBuf) -> Result<impl Write> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(&filename)
        .map_err(|e| Error::OpenFile(e, filename))?;
    Ok(file)
}
