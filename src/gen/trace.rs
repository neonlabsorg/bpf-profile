//! bpf-profile trace module.

use super::{Error, Result};
use lazy_static::lazy_static;
use regex::Regex;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
//use tracing::info;

/// Opens the trace file for reading.
pub fn open(filename: PathBuf) -> Result<impl Read> {
    let file = File::open(&filename).map_err(|e| Error::OpenFile(e, filename))?;
    Ok(file)
}

/// Represents trace instruction (call or another).
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
