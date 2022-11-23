//! bpf-profile file buffered utilities module.

use crate::error::{Error, Result};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

/// Opens a file for buffered reading.
pub fn open(filepath: &Path) -> Result<impl BufRead> {
    let file = File::open(filepath).map_err(|e| Error::OpenFile(e, filepath.into()))?;
    Ok(BufReader::new(file))
}

/// Opens a file for buffered writing; rewrites existing.
pub fn open_w(filepath: &Path) -> Result<impl Write> {
    if filepath.exists() {
        fs::remove_file(filepath)?;
    }
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(filepath)
        .map_err(|e| Error::OpenFile(e, filepath.into()))?;
    Ok(BufWriter::new(file))
}

/// Reads all bytes until a newline (the `0xA` byte) is reached,
/// and puts them to the provided buffer replacing the buffer's contents.
pub fn read_line(reader: &mut impl BufRead, line: &mut String) -> Result<usize> {
    line.clear();
    reader
        .read_line(line)
        .map_err(|e| Error::ReadLine(e, line.clone()))
}
