//! bpf-profile asm module.

use crate::config::ProgramCounter;

/// Represents BPF instruction (call or another).
#[derive(Debug, Default, Clone, PartialEq, PartialOrd)]
pub struct Instruction {
    pc: ProgramCounter,
    text: String,
}

use super::{Error, Result};
use crate::config::Address;
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

    /// Returns true if default instruction.
    pub fn is_empty(&self) -> bool {
        self.pc == 0 && self.text.is_empty()
    }

    /// Returns program counter of the instruction.
    pub fn pc(&self) -> ProgramCounter {
        self.pc
    }

    /// Returns copy of the textual representation.
    pub fn text(&self) -> String {
        self.text.clone()
    }

    /// Checks if the instruction is a call of function.
    pub fn is_call(&self) -> bool {
        self.text.starts_with("call")
    }

    /// Checks if the instruction is exit of function.
    pub fn is_exit(&self) -> bool {
        self.text == "exit"
    }

    /// Returns address of a call target or error if instruction is not a call.
    pub fn extract_call_target(&self, lc: usize) -> Result<Address> {
        if !self.is_call() {
            return Err(Error::TraceNotCall(self.text(), lc));
        }
        let mut pair = self.text.split_whitespace(); // => "call something"
        let _ = pair
            .next()
            .ok_or_else(|| Error::TraceParsing(self.text(), lc))?;
        let address = pair
            .next()
            .ok_or_else(|| Error::TraceParsing(self.text(), lc))?;
        Ok(hex_str_to_address(address))
    }
}

use std::fmt;

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_empty() {
            write!(f, "")
        } else {
            write!(f, "{}:\t\t{}", self.pc + 1, &self.text)
        }
    }
}

/// Represents generated assembly file.
#[derive(Debug)]
pub struct Source {
    ixs: Vec<Instruction>,
}

use super::dump::Resolver;
use std::io::Write;

impl Source {
    /// Creates new instance of Source.
    pub fn new() -> Self {
        Source { ixs: Vec::new() }
    }

    /// Adds new instruction to the listing.
    pub fn add_instruction(&mut self, ix: &Instruction) {
        let index = ix.pc();
        if index >= self.ixs.len() {
            self.ixs.resize(index + 1, Instruction::default());
        }
        if self.ixs[index].is_empty() {
            self.ixs[index] = ix.clone();
        } else if self.ixs[index] != *ix {
            panic!(
                "Inconsistent input: expected '{}', got '{}'",
                &self.ixs[index], &ix
            );
        }
    }

    /// Writes all lines of the listing to a file.
    pub fn write(&self, mut output: impl Write, resolver: &Resolver) -> Result<()> {
        for i in 0..self.ixs.len() {
            let ix = &self.ixs[i];
            if i == 0 && ix.is_empty() {
                writeln!(output, "Generated BPF assembly code for QCacheGrind")?;
                continue;
            }
            if ix.is_call() {
                let address = ix.extract_call_target(i)?;
                let name = resolver.resolve(address);
                let ix = Instruction {
                    pc: ix.pc(),
                    text: format!("call {}", &name),
                };
                writeln!(output, "{}", ix)?;
                continue;
            }
            writeln!(output, "{}", ix)?;
        }
        output.flush()?;
        Ok(())
    }
}

/// Converts a hex number string representation to integer Address.
fn hex_str_to_address(s: &str) -> Address {
    let a = s.trim_start_matches("0x");
    Address::from_str_radix(a, 16).expect("Invalid address")
}
