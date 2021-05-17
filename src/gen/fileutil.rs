//! bpf-profile file utilities module.

use super::{Error, Result};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, Read, Write};
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

/// Reads all bytes until a newline (the `0xA` byte) is reached,
/// and puts them to the provided buffer replacing the buffer's contents.
pub fn read_line(reader: &mut impl BufRead, line: &mut String) -> Result<usize> {
    line.clear();
    reader
        .read_line(line)
        .map_err(|e| Error::ReadLine(e, line.clone()))
}
