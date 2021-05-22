//! bpf-profile asm module.

use crate::config::ProgramCounter;

/// Represents BPF instruction (call or another).
#[derive(Debug)]
pub struct Instruction {
    pc: ProgramCounter,
    text: String,
}

use super::{Error, Result};
use lazy_static::lazy_static;
use regex::Regex;

impl Instruction {
    /// Parses the input string and creates corresponding instruction if possible.
    pub fn parse(s: &str) -> Result<Self> {
        lazy_static! {
            static ref TRACE_INSTRUCTION: Regex =
                Regex::new(r"\d+\s+\[.+\]\s+(\d+):\s+(.+)").expect("Invalid regex");
        }

        if let Some(caps) = TRACE_INSTRUCTION.captures(s) {
            let pc = caps[1]
                .parse::<ProgramCounter>()
                .expect("Cannot parse program counter");
            let text = caps[2].trim().to_string();
            return Ok(Instruction { pc, text });
        }

        Err(Error::TraceSkipped)
    }

    /// Returns copy of the textual representation.
    pub fn text(&self) -> String {
        self.text.clone()
    }

    /// Returns program counter of the instruction.
    pub fn pc(&self) -> ProgramCounter {
        self.pc
    }

    /// Checks if the instruction is a call of function.
    pub fn is_call(&self) -> bool {
        self.text.starts_with("call")
    }

    /// Checks if the instruction is exit of function.
    pub fn is_exit(&self) -> bool {
        self.text == "exit"
    }
}

/// Represents generated assembly file.
#[derive(Debug)]
pub struct Source {
    lines: Vec<String>,
}

use std::io::Write;

impl Source {
    /// Creates new instance of Source.
    pub fn new() -> Self {
        Source { lines: Vec::new() }
    }

    /// Adds new instruction to the listing.
    pub fn add_instruction(&mut self, index: usize, text: &str) {
        if index >= self.lines.len() {
            self.lines.resize(index + 1, String::default());
        }
        let generated = format!("{}:\t\t {}", index + 1, text);
        if self.lines[index].is_empty() {
            self.lines[index] = generated;
        } else if !self.lines[index].starts_with(&generated) {
            panic!(
                "Inconsistent input: expected '{}', got '{}'",
                &self.lines[index], &generated
            );
        }
    }

    /// Writes all lines of the listing to a file.
    pub fn write(&self, mut output: impl Write) -> Result<()> {
        for line in &self.lines {
            writeln!(output, "{}", line)?;
        }
        output.flush()?;
        Ok(())
    }
}
