//! bpf_profile trace module.

use super::{Error, Result};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
//use tracing::info;

/// Opens the trace file for reading.
pub fn open(filename: PathBuf) -> Result<impl Read> {
    let file = File::open(&filename).map_err(|e| Error::OpenFile(e, filename))?;
    Ok(file)
}

//pub struct Instruction {}
