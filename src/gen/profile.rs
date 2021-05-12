//! bpf-profile implementation of the profile struct.

use super::dump::Object;
use super::trace::{self, Instruction};
use super::{Error, Result};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

/// Represents the profile.
#[derive(Debug)]
pub struct Profile {
    file: String,
    entrypoint: Call,
    functions: HashMap<String, Function>,
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
            entrypoint: Call::new("entrypoint"),
            functions: HashMap::new(),
        };

        let reader = BufReader::new(trace::open(trace_file)?);
        parse_trace_file(reader, &mut prof)?;
        Ok(prof)
    }

    /// Writes the profile data in the callgrind file format.
    /// See details of the format in the Valgrind documentation.
    pub fn write_callgrind(&self, mut output: impl Write) -> Result<()> {
        writeln!(output, "# callgrind format")?;
        writeln!(output, "version: 1")?;
        writeln!(output, "creator: bpf-profile")?;
        writeln!(output, "events: Instructions")?;
        writeln!(output, "totals: {}", self.entrypoint.total_cost())?;
        writeln!(output, "fl={}", self.file)?;
        write_callgrind_functions(&self.functions, output)?;
        Ok(())
    }

    /// Increments the total cost and the cost of current call.
    fn increment_cost(&mut self) {
        self.entrypoint.increment_cost();
    }

    /// Adds next call to the stack.
    fn push_call(&mut self, call: Call) {
        let address = call.address.clone();
        self.entrypoint.push_call(call);
        if !self.functions.contains_key(&address) {
            self.functions
                .insert(address.clone(), Function::new(&address));
        }
    }

    /// Removes finished call from the stack and adds it to the caller.
    fn pop_call(&mut self) {
        let call = self.entrypoint.pop_call();
        self.functions.get_mut(&call.caller).unwrap().add_call(call);
    }
}

/// Represents a function call.
#[derive(Clone, Debug)]
struct Call {
    address: String,
    caller: String,
    cost: usize,
    finished_calls: usize,
    frame: usize,
    calls: Vec<Call>,
}

impl Call {
    /// Creates new call object.
    fn new(address: &str) -> Self {
        Call {
            address: address.into(),
            caller: String::default(),
            cost: 0,
            finished_calls: 0,
            frame: 0,
            calls: Vec::new(),
        }
    }

    /// Creates new call object from a trace instruction (which must be a call).
    fn from(ix: Instruction, lc: usize) -> Result<Self> {
        let text = ix.text();
        if !ix.is_call() {
            return Err(Error::NotCall(text));
        }
        let mut pair = text.split_whitespace(); // => "call something"
        let _ = pair.next().ok_or_else(|| Error::Parsing(ix.text(), lc))?;
        let addr = pair.next().ok_or_else(|| Error::Parsing(ix.text(), lc))?;
        Ok(Call::new(addr))
    }

    /// Increments the cost of this call.
    fn increment_cost(&mut self) {
        if self.frame == 0 {
            self.cost += 1;
        } else {
            let index = self.finished_calls + self.frame;
            self.calls[index].increment_cost();
        }
    }

    /// Adds next call to the stack.
    fn push_call(&mut self, mut call: Call) {
        if self.frame == 0 {
            call.caller = self.address.clone();
            self.calls.push(call);
            self.frame += 1;
        } else {
            let index = self.finished_calls + self.frame;
            call.caller = self.calls[index].address.clone();
            self.calls[index].push_call(call);
        }
    }

    /// Removes current call from the stack.
    fn pop_call(&mut self) -> Call {
        let index = self.finished_calls + self.frame;
        let call = self.calls[index].clone();
        if self.frame > 0 {
            self.frame -= 1;
        } else {
            self.finished_calls += 1;
        }
        call
    }

    /// Returns cost of the call and of all enclosed calls.
    fn total_cost(&self) -> usize {
        self.calls
            .iter()
            .fold(self.cost, |sum, c| sum + c.total_cost())
    }
}

/// Represents a function.
#[derive(Debug)]
struct Function {
    address: String,
    cost: usize,
    calls: Vec<Call>,
}

impl Function {
    /// Creates new function object.
    fn new(addr: &str) -> Self {
        Function {
            address: addr.into(),
            cost: 0,
            calls: Vec::new(),
        }
    }

    /// Adds enclosed call for this function.
    fn add_call(&mut self, call: Call) {
        self.calls.push(call);
    }
}

/// Parses the trace file line by line building the Profile instance.
fn parse_trace_file(mut reader: impl BufRead, prof: &mut Profile) -> Result<()> {
    // reuse string in the loop for better performance
    let mut line = String::with_capacity(512);
    let mut bytes_read = usize::MAX;
    let mut lc = 0_usize;

    while bytes_read != 0 {
        lc += 1;
        line.clear();
        bytes_read = reader
            .read_line(&mut line)
            .map_err(|e| Error::ReadLine(e, line.clone()))?;

        let ix = Instruction::parse(&line, lc);
        if let Err(Error::Skipped) = &ix {
            //warn!("Skip '{}'", &line.trim());
            continue;
        }
        let ix = ix?;

        prof.increment_cost();
        if ix.is_exit() {
            prof.pop_call();
        }
        if ix.is_call() {
            prof.push_call(Call::from(ix, lc)?);
        }
    }

    Ok(())
}

/// Writes information about calls of functions and their costs.
fn write_callgrind_functions(
    functions: &HashMap<String, Function>,
    mut output: impl Write,
) -> Result<()> {
    for (a, f) in functions {
        writeln!(output)?;
        writeln!(output, "fn={}", a)?;
        writeln!(output, "0 {}", f.cost)?;
    }

    Ok(())
}
