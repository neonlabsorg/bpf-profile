//! bpf-profile trace module.

use crate::error::Result;
use crate::filebuf;
use lazy_static::lazy_static;
use regex::Regex;
use std::io::BufRead;

/// Checks the trace file contains expected header line.
pub fn contains_standard_header(mut reader: impl BufRead) -> Result<bool> {
    lazy_static! {
        static ref TRACE_HEADER: Regex =
            Regex::new(r"\[.+\s+TRACE\s+.+BPF Program Instruction Trace").expect("Invalid regex");
    }

    let mut line = String::with_capacity(512);
    let mut bytes_read = usize::MAX;

    while bytes_read != 0 {
        bytes_read = filebuf::read_line(&mut reader, &mut line)?;
        if TRACE_HEADER.is_match(&line) {
            return Ok(true);
        }
    }

    Ok(false)
}
