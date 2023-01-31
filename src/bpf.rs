//! bpf-profile bpf module.

use std::fmt;

use lazy_static::lazy_static;
use regex::Regex;

use crate::{Address, ProgramCounter};
use crate::PADDING;
use crate::error::{Error, Result};

/// Represents parsed BPF instruction data.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd)]
pub enum InstructionData {
    /// Default (empty) instruction.
    Empty,
    /// Call instruction.
    Call(Address),
    /// CallX instruction.
    CallX(Address),
    /// Exit instruction.
    Exit,
    /// Other instruction (none of above).
    Other,
}

impl Default for InstructionData {
    fn default() -> Self {
        Self::Empty
    }
}

impl InstructionData {
    fn parse(s: &str, lc: usize) -> Result<Self> {
        let s = s.trim();

        if s.is_empty() {
            return Ok(InstructionData::Empty);
        }

        if Self::is_exit(s) {
            return Ok(InstructionData::Exit);
        }

        // TODO: This code is obsolete, need to update.
        //       Call instruction now has format: "call LABEL" where LABEL is an identifier of
        //       a label in the code, or "[invalid]" if label not found.
        //       CallX instruction now has format "callx rXXX", where XXX is an i64 decimal
        //       register index.
        if Self::is_call(s) {
            let mut pair = s.split_whitespace(); // => "call something"
            let operation = pair
                .next()
                .ok_or_else(|| Error::TraceParsing(s.into(), lc))?;
            let target = pair
                .next()
                .ok_or_else(|| Error::TraceParsing(s.into(), lc))?;
            let target = hex_str_to_address(target);
            return match operation {
                "call" => Ok(InstructionData::Call(target)),
                "callx" => Ok(InstructionData::Call(target)),
                _ => Err(Error::TraceParsing(s.into(), lc)),
            }
        }

        Ok(InstructionData::Other)
    }

    /// Checks if the instruction is a call of function.
    fn is_call(text: &str) -> bool {
        text.starts_with("call")
    }

    /// Checks if the instruction is exit of function.
    fn is_exit(text: &str) -> bool {
        text == "exit"
    }
}

/// Represents BPF instruction (call or another).
#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd)]
pub struct Instruction {
    pc: ProgramCounter,
    data: InstructionData,
    text: String,
    bpf_units: Option<u64>,
}

impl Instruction {
    /// Creates new instance of Instruction.
    pub const fn new(
        pc: ProgramCounter,
        data: InstructionData,
        text: String,
        bpf_units: Option<u64>,
    ) -> Self {
        Self { pc, data, text, bpf_units }
    }

    /// Parses the input string and creates corresponding instruction if possible.
    pub fn parse(s: &str, lc: usize) -> Result<Self> {
        lazy_static! {
            static ref TRACE_INSTRUCTION: Regex =
                Regex::new(r"\d+\s+\[.+\]\s+(\d+):\s+(.+)").expect("Invalid regex");
        }

        if let Some(caps) = TRACE_INSTRUCTION.captures(s) {
            let pc = caps[1]
                .parse::<ProgramCounter>()
                .unwrap_or_else(|_| panic!("Cannot parse program counter in instruction #{}", lc));
            let text = caps[2].trim().to_string();
            let data = InstructionData::parse(&text, lc)?;
            return Ok(Instruction { pc, data, text, bpf_units: None });
        }

        Err(Error::TraceSkipped(s.to_string()))
    }

    /// Returns true if default instruction.
    pub fn is_empty(&self) -> bool {
        self.data == InstructionData::Empty
    }

    /// Returns program counter of the instruction.
    pub fn pc(&self) -> ProgramCounter {
        self.pc
    }

    /// Returns copy of the instruction data.
    pub fn data(&self) -> InstructionData {
        self.data.clone()
    }

    /// Returns copy of the textual representation.
    pub fn text(&self) -> String {
        self.text.clone()
    }

    /// Returns BPF units count, consumed by the instruction.
    pub fn bpf_units(&self) -> Option<u64> {
        self.bpf_units
    }

    /// Checks if the instruction is a call of function.
    pub fn is_call(&self) -> bool {
        matches!(&self.data, InstructionData::Call(_) | InstructionData::CallX(_))
    }

    /// Checks if the instruction is exit of function.
    pub fn is_exit(&self) -> bool {
        self.data == InstructionData::Exit
    }

    /// Returns "call" or "callx" or error if instruction is not a call.
    pub fn call_operation(&self, lc: usize) -> Result<String> {
        match &self.data {
            InstructionData::Call(_) => Ok("call".into()),
            InstructionData::CallX(_) => Ok("callx".into()),
            _ => Err(Error::TraceNotCall(self.text(), lc)),
        }
    }

    /// Returns address of a call target or error if instruction is not a call.
    pub fn call_target(&self, lc: usize) -> Result<Address> {
        match &self.data {
            InstructionData::Call(target) | InstructionData::CallX(target) => Ok(*target),
            _ => Err(Error::TraceNotCall(self.text(), lc)),
        }
    }

    pub(crate) fn compare_asm(&self, other: &Instruction) -> bool {
        self.pc == other.pc && match &self.data {
            InstructionData::CallX(_) => matches!(other.data, InstructionData::CallX(_)),
            _=> self.data == other.data,
        }
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_empty() {
            return write!(f, "");
        }
        write!(f, "{}:{}{}", self.pc, PADDING, &self.text)
    }
}

/// Converts hex number string representation to integer Address.
fn hex_str_to_address(s: &str) -> Address {
    let a = s.trim_start_matches("0x");
    Address::from_str_radix(a, 16).expect("Invalid address")
}
