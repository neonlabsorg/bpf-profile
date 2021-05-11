//! bpf_profile implementation of the profile struct.

use super::dump::Object;
use super::Result;
use std::io::{BufRead, Write};

/// Represents the profile.
pub struct Profile {
    calls: Vec<Call>,
}

impl Profile {
    /// Reads the trace and creates the profile data.
    pub fn create(_trace: impl BufRead, _dump: &Object) -> Result<Self> {
        let mut prof = Profile { calls: Vec::new() };
        prof.calls.push(Call::new());

        // reuse string for better performance
        //let line = String::with_capacity(1024);
        //for line in trace.lines() {
        //    let ix = trace::Instruction::new(&line);
        //}

        Ok(prof)
    }

    /// Writes the profile data in the callgrind file format.
    /// See details of the format in the Valgrind documentation.
    pub fn write_callgrind(&self, _output: impl Write) -> Result<()> {
        for call in &self.calls {
            tracing::info!("{:?}", call);
        }
        Ok(())
    }
}

/// Represents a function call.
#[derive(Debug)]
struct Call {
    cost: usize,
    calls: Vec<Call>,
}

impl Call {
    fn new() -> Self {
        Call {
            cost: 0,
            calls: Vec::new(),
        }
    }
}
