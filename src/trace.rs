//! bpf-profile trace module.

use crate::{error::Result, filebuf};
use std::io::BufRead;

const HEADER: &str = "BPF Program Instruction Trace";

/// Checks the trace file contains expected header line.
pub fn contains_standard_header(mut reader: impl BufRead) -> Result<bool> {
    let mut line = String::with_capacity(512);
    let mut bytes_read = usize::MAX;

    while bytes_read != 0 {
        bytes_read = filebuf::read_line(&mut reader, &mut line)?;
        if line.contains(HEADER) {
            return Ok(true);
        }
    }

    Ok(false)
}
