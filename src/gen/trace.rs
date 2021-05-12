//! bpf_profile trace module.

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
    frame: usize,
    text: String,
}

impl Instruction {
    /// Parses the input string and creates corresponding instruction if possible.
    pub fn parse(s: &str) -> Option<Self> {
        lazy_static! {
            static ref RE: Regex = Regex::new(
                r"\[\d{4}-\d{2}-\d{2}.+\s+TRACE\s+.+\s+BPF:\s+.+\s+frame\s+(\d+)\s+pc\s+(\d+)\s+(.+)"
            )
            .expect("Incorrect regular expression");
        }

        dbg!(&s);
        dbg!(RE.is_match(s));
        RE.captures(s).map(|caps| {
            dbg!(caps[0].to_string());
            dbg!(caps[1].to_string());
            dbg!(caps[2].to_string());
            dbg!(caps[3].to_string());
            let frame = 0_usize;
            let text = String::from(s);
            Instruction { frame, text }
        })
    }

    /// Returns frame of the instruction.
    pub fn frame(&self) -> usize {
        self.frame
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
