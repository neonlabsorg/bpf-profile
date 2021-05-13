//! bpf-profile output module.

use super::{Error, Result};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
//use tracing::info;

/// Opens output file for writing.
pub fn open_w(filename: PathBuf) -> Result<impl Write> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(&filename)
        .map_err(|e| Error::OpenFile(e, filename))?;
    Ok(file)
}
