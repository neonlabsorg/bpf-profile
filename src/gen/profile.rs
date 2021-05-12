//! bpf_profile implementation of the profile struct.

use super::dump::Object;
use super::trace::{self, Instruction};
use super::{Error, Result};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

/// Represents the profile.
pub struct Profile {
    file: String,
    total_cost: usize,
    stack: Vec<usize>,
    calls: Vec<Call>, // main vector of calls
}

impl Profile {
    /// Reads the trace and creates the profile data.
    pub fn create(trace_file: PathBuf, _dump: &Object) -> Result<Self> {
        let file = trace_file
            .to_str()
            .ok_or_else(|| Error::Filename(trace_file.clone()))?
            .to_string();

        let mut prof = Profile {
            file,
            total_cost: 0,
            stack: Vec::new(),
            calls: Vec::new(),
        };

        let reader = BufReader::new(trace::open(trace_file)?);
        parse_trace_file(reader, &mut prof)?;
        Ok(prof)
    }

    /// Writes the profile data in the callgrind file format.
    /// See details of the format in the Valgrind documentation.
    pub fn write_callgrind(&self, mut output: impl Write) -> Result<()> {
        writeln!(output, "# callgrind format")?;
        writeln!(output, "events: Instructions")?;
        writeln!(output, "fl={}", self.file)?;
        Ok(())
    }

    /// Increments the total cost and the cost of current call.
    fn increment_cost(&mut self) {
        self.total_cost += 1;
        if let Some(curr_call_index) = self.stack.last() {
            self.calls[*curr_call_index].increment_cost();
        }
    }

    /// Adds next call to the stack.
    fn push_call(&mut self, call: Call) {
        let call_index = self.calls.len();
        self.calls.push(call);
        if let Some(curr_call_index) = self.stack.last() {
            self.calls[*curr_call_index].push_call(call_index);
        }
        self.stack.push(call_index);
    }

    /// Removes current call from the stack.
    fn pop_call(&mut self) -> Result<()> {
        self.stack.pop().ok_or(Error::EmptyStack)?;
        Ok(())
    }
}

/// Represents a function call.
#[derive(Debug)]
struct Call {
    address: String,
    cost: usize,
    calls: Vec<usize>, // indices in the main vector of calls
}

impl Call {
    /// Creates new call object.
    fn new(addr: &str) -> Self {
        Call {
            address: addr.into(),
            cost: 0,
            calls: Vec::new(),
        }
    }

    /// Creates new call object from a trace instruction (which must be a call).
    fn from(ix: Instruction) -> Result<Self> {
        let text = ix.text();
        if !ix.is_call() {
            return Err(Error::NotCall(text));
        }
        let mut pair = text.split_whitespace();
        let call = Call::new(pair.next().ok_or_else(|| Error::Parsing(ix.text()))?);
        Ok(call)
    }

    /// Increments the cost of this call.
    fn increment_cost(&mut self) {
        self.cost += 1;
    }

    /// Adds next call index.
    fn push_call(&mut self, call_index: usize) {
        self.calls.push(call_index);
    }
}

/// Parses the trace file line by line building the Profile instance.
fn parse_trace_file(mut reader: impl BufRead, prof: &mut Profile) -> Result<()> {
    // reuse string in the loop for better performance
    let mut line = String::with_capacity(512);
    let mut bytes_read = usize::MAX;

    while bytes_read != 0 {
        line.clear();
        bytes_read = reader
            .read_line(&mut line)
            .map_err(|e| Error::ReadLine(e, line.clone()))?;
        let ix = Instruction::parse(&line);
        if let Some(ix) = ix {
            if ix.frame() != prof.stack.len() {
                return Err(Error::FrameMismatch);
            }
            if ix.is_call() {
                prof.push_call(Call::from(ix)?);
            } else {
                prof.increment_cost();
                if ix.is_exit() {
                    prof.pop_call()?;
                }
            }
        }
    }

    Ok(())
}
