//! bpf-profile implementation of the profile struct.

use super::dump::Object;
use super::trace::{self, Instruction};
use super::{Error, Result};
use crate::config::GROUND_ZERO;
use maplit::hashmap;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

type Functions = HashMap<String, Function>;

/// Represents the profile.
#[derive(Debug)]
pub struct Profile {
    file: String,
    entrypoint: Call,
    functions: Functions,
}

impl Profile {
    /// Reads the trace and creates the profile data.
    pub fn create(trace_file: PathBuf, _dump: &Object) -> Result<Self> {
        tracing::debug!("Profile.create {:?}", &trace_file);

        let file = trace_file
            .to_str()
            .ok_or_else(|| Error::Filename(trace_file.clone()))?
            .to_string();

        let mut prof = Profile {
            file,
            entrypoint: Call::new(GROUND_ZERO),
            functions: hashmap! { GROUND_ZERO.to_string() => Function::new(GROUND_ZERO) },
        };

        let reader = BufReader::new(trace::open(&trace_file)?);
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
        writeln!(
            output,
            "totals: {}",
            self.functions[GROUND_ZERO].total_cost()
        )?;
        writeln!(output, "fl={}", self.file)?;
        write_callgrind_functions(&self.functions, output)?;
        Ok(())
    }

    /// Increments the total cost and the cost of current call.
    fn increment_cost(&mut self) {
        tracing::debug!("Profile.increment_cost");
        self.entrypoint.increment_cost(&mut self.functions);
    }

    /// Adds next call to the stack.
    fn push_call(&mut self, call: Call) {
        tracing::debug!("Profile.push_call {}", &call.address);
        let address = call.address.clone();
        self.entrypoint.push_call(call);
        if !self.functions.contains_key(&address) {
            tracing::debug!("Add function to registry: {}", &address);
            self.functions
                .insert(address.clone(), Function::new(&address));
        }
    }

    /// Removes finished call from the stack and adds it to the caller.
    fn pop_call(&mut self) {
        let call = self.entrypoint.pop_call();
        tracing::debug!("Profile.pop_call {}", &call.address);
        //dbg!(&call);
        if !call.caller.is_empty() {
            self.functions.get_mut(&call.caller).unwrap().add_call(call);
        }
    }
}

/// Represents a function call.
#[derive(Clone, Debug)]
struct Call {
    address: String,
    caller: String,
    cost: usize,
    calls: Vec<Call>,
}

impl Call {
    /// Creates new call object.
    fn new(address: &str) -> Self {
        Call {
            address: address.into(),
            caller: String::default(),
            cost: 0,
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
        let address = pair.next().ok_or_else(|| Error::Parsing(ix.text(), lc))?;
        Ok(Call::new(address))
    }

    /// Increments the cost of this call.
    fn increment_cost(&mut self, functions: &mut Functions) {
        tracing::debug!("Call({}).increment_cost", self.address);
        if self.calls.is_empty() {
            self.cost += 1;
            functions.get_mut(&self.address).unwrap().increment_cost();
        } else {
            let last_index = self.calls.len() - 1;
            assert!(last_index == 0);
            self.calls[last_index].increment_cost(functions);
        }
    }

    /// Adds next call to the stack.
    fn push_call(&mut self, mut call: Call) {
        tracing::debug!("Call({}).push_call {}", self.address, call.address);
        if self.calls.is_empty() {
            call.caller = self.address.clone();
            self.calls.push(call);
        } else {
            let last_index = self.calls.len() - 1;
            assert!(last_index == 0);
            self.calls[last_index].push_call(call);
        }
    }

    /// Removes current call from the stack.
    fn pop_call(&mut self) -> Call {
        tracing::debug!("Call({}).pop_call", self.address);
        assert!(!self.calls.is_empty());
        let last_index = self.calls.len() - 1;
        assert!(last_index == 0);
        if !self.calls[last_index].calls.is_empty() {
            self.calls[last_index].pop_call()
        } else {
            let call = self.calls.pop().unwrap();
            self.cost += call.cost;
            call
        }
    }
}

/// Represents a function which will be dumped into a profile.
#[derive(Debug)]
struct Function {
    address: String,
    cost: usize,
    calls: Vec<Call>,
}

impl Function {
    /// Creates new function object.
    fn new(address: &str) -> Self {
        Function {
            address: address.into(),
            cost: 0,
            calls: Vec::new(),
        }
    }

    /// Increments the immediate cost of the function.
    fn increment_cost(&mut self) {
        tracing::debug!("Function({}).increment_cost", self.address);
        self.cost += 1;
    }

    /// Adds finished enclosed call for this function.
    fn add_call(&mut self, call: Call) {
        tracing::debug!("Function({}).add_call {}", self.address, call.address);
        self.calls.push(call);
    }

    /// Returns cost of the function and of it's enclosed calls.
    fn total_cost(&self) -> usize {
        self.calls.iter().fold(self.cost, |sum, c| sum + c.cost)
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
        //tracing::debug!("{}", &line);

        let ix = Instruction::parse(&line, lc);
        tracing::debug!("");
        tracing::debug!("ix {:?}", &ix);
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
fn write_callgrind_functions(functions: &Functions, mut output: impl Write) -> Result<()> {
    let mut statistics = HashMap::new();

    for (a, f) in functions {
        if a == GROUND_ZERO {
            continue;
        }
        writeln!(output)?;
        writeln!(output, "fn={}", a)?;
        writeln!(output, "0 {}", f.cost)?;
        statistics.clear();
        for c in &f.calls {
            if !statistics.contains_key(&c.address) {
                statistics.insert(c.address.clone(), (1, c.cost));
            } else {
                let mut stat = statistics[&c.address];
                stat.0 += 1;
                stat.1 += c.cost;
                statistics.insert(c.address.clone(), stat);
            }
        }
        for (a, s) in &statistics {
            writeln!(output, "cfn={}", a)?;
            writeln!(output, "calls={} {}", s.0, 0)?;
            writeln!(output, "{} {}", 0, s.1)?;
        }
    }

    Ok(())
}
