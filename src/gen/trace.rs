//! bpf-profile trace module.

use super::{fileutil, Error, Result};
use lazy_static::lazy_static;
use regex::Regex;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Checks the trace file contains expected header line.
pub fn contains_standard_header(filename: &Path) -> Result<bool> {
    contains_standard_header_(BufReader::new(fileutil::open(filename)?))
}

/// Checks the trace file contains expected header line.
pub fn contains_standard_header_(mut reader: impl BufRead) -> Result<bool> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"\[.+\s+TRACE\s+.+BPF Program Instruction Trace")
            .expect("Incorrect regular expression");
    }

    // reuse string in the loop for better performance
    let mut line = String::with_capacity(512);
    let mut bytes_read = usize::MAX;

    while bytes_read != 0 {
        line.clear();
        bytes_read = reader
            .read_line(&mut line)
            .map_err(|e| Error::ReadLine(e, line.clone()))?;
        if RE.is_match(&line) {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Represents trace instruction (call or another).
#[derive(Debug)]
pub struct Instruction {
    _pc: usize,
    text: String,
}

impl Instruction {
    /// Parses the input string and creates corresponding instruction if possible.
    pub fn parse(s: &str, lc: usize) -> Result<Self> {
        lazy_static! {
            static ref RE: Regex =
                Regex::new(r"\d+\s+\[.+\]\s+(\d+):\s+(.+)").expect("Incorrect regular expression");
        }

        if let Some(caps) = RE.captures(s) {
            let pc = caps[1]
                .parse::<usize>()
                .map_err(|_| Error::Parsing(s.into(), lc))?;
            let text = caps[2].to_string();
            return Ok(Instruction { _pc: pc, text });
        }

        Err(Error::Skipped)
    }

    /// Returns copy of the textual representation.
    pub fn text(&self) -> String {
        self.text.clone()
    }

    /// Checks if the instruction is a call of a function.
    pub fn is_call(&self) -> bool {
        self.text.starts_with("call")
    }

    /// Checks if the instruction is exit of a function.
    pub fn is_exit(&self) -> bool {
        self.text == "exit"
    }
}
