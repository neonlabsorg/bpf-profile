//! bpf-profile-generate trace module.
//! Implements parsing of the trace file and generating the profile.

use super::asm;
use super::profile::{self, Call, Function, Functions};
use crate::config::{Cost, Map, ProgramCounter, GROUND_ZERO};
use crate::error::{Error, Result};
use crate::resolver::{self, Resolver};
use crate::{filebuf, global};
use std::io::{BufRead, Write};
use std::path::Path;

/// Represents the profile.
#[derive(Debug)]
pub struct Profile {
    total_cost: Cost,
    ground: Call,
    functions: Functions,
    resolver: Resolver,
    asm: Option<asm::Source>,
}

use crate::bpf::Instruction;

impl Profile {
    /// Creates the initial instance of profile.
    pub fn new(resv: Resolver, asm_path: Option<&Path>) -> Result<Self> {
        let mut functions = Map::new();
        functions.insert(GROUND_ZERO, Function::ground_zero());
        Ok(Profile {
            total_cost: 0,
            ground: Call::new(GROUND_ZERO, 0),
            functions,
            resolver: resv,
            asm: asm_path.map(asm::Source::new),
        })
    }

    /// Reads the trace and creates the profile data.
    pub fn create(
        trace_path: &Path,
        dump_path: Option<&Path>,
        asm_path: Option<&Path>,
    ) -> Result<Self> {
        tracing::debug!("Profile.create {:?}", trace_path);

        let resv = resolver::read(dump_path)?;
        let reader = filebuf::open(trace_path)?;
        let mut prof = Profile::new(resv, asm_path)?;
        parse(reader, &mut prof)?;

        Ok(prof)
    }

    /// Writes the profile data in the callgrind file format.
    /// See details of the format in the Valgrind documentation.
    pub fn write_callgrind(&self, mut output: impl Write, asm_fl: &str) -> Result<()> {
        if self.asm.is_some() {
            let asm = self.asm.as_ref().unwrap();
            asm.write(&self.resolver)?;
        }

        writeln!(output, "# callgrind format")?;
        writeln!(output, "version: 1")?;
        writeln!(output, "creator: bpf-profile")?;
        writeln!(output, "positions: line")?;
        writeln!(output, "events: Instructions")?;
        writeln!(output, "totals: {}", self.total_cost)?;
        writeln!(output, "fl={}", asm_fl)?;
        profile::write_callgrind_functions(output, &self.functions, self.asm.is_some())?;

        Ok(())
    }

    /// Adds instruction to the generated assembly listing.
    fn keep_asm(&mut self, ix: &Instruction) {
        let _ = self.asm.as_mut().map(|a| a.add_instruction(ix));
    }

    /// Increments the total cost and the cost of current call.
    fn increment_cost(&mut self, pc: ProgramCounter) {
        tracing::debug!("Profile.increment_cost");
        self.total_cost += 1;
        self.ground.increment_cost(pc, &mut self.functions);
    }

    /// Adds next call to the call stack.
    fn push_call(&mut self, call: Call, first_pc: ProgramCounter) {
        let address = call.address();
        tracing::debug!("Profile.push_call 0x{:x}", address);
        self.ground.push_call(call);
        #[allow(clippy::map_entry)]
        if !self.functions.contains_key(&address) {
            tracing::debug!("Add function to the registry: 0x{:x}", address);
            let func = Function::new(address, first_pc, &mut self.resolver);
            self.functions.insert(address, func);
        }
    }

    /// Removes finished call from the call stack and adds it to the caller.
    fn pop_call(&mut self) {
        let call = self.ground.pop_call();
        tracing::debug!("Profile.pop_call 0x{:x}", &call.address());
        if !call.is_ground() {
            let f = self
                .functions
                .get_mut(&call.caller())
                .expect("Caller not found in registry of functions");
            f.add_call(call);
        }
    }
}

/// Parses the trace file line by line, building the Profile instance.
pub fn parse(mut reader: impl BufRead, prof: &mut Profile) -> Result<()> {
    if global::verbose() {
        tracing::info!("Parsing trace file, creating profile...")
    }

    let mut line = String::with_capacity(512);
    let mut bytes_read = usize::MAX;
    let mut lc = 0_usize;
    let mut ix: Instruction;

    while bytes_read != 0 {
        if line.is_empty() {
            bytes_read = filebuf::read_line(&mut reader, &mut line)?;
            lc += 1;
        }

        let ixr = Instruction::parse(&line);
        if let Err(Error::TraceSkipped) = &ixr {
            /* warn!("Skip '{}'", &line.trim()); */
            line.clear();
            continue;
        }
        ix = ixr?;

        prof.keep_asm(&ix);

        if ix.is_exit() {
            prof.increment_cost(ix.pc());
            prof.pop_call();
            line.clear();
            continue;
        }

        if !ix.is_call() {
            prof.increment_cost(ix.pc());
            line.clear();
            continue;
        }

        // Handle sequences of enclosed calls as well:
        // 604: call 0xcb3fc071
        // 588: call 0x8e0001f9
        // 1024: call 0x8bf38212
        // ...
        while ix.is_call() {
            prof.increment_cost(ix.pc());
            let call = Call::from(&ix, lc)?;
            // Read next line — the first instruction of the call
            bytes_read = filebuf::read_line(&mut reader, &mut line)?;
            lc += 1;
            ix = Instruction::parse(&line)?;
            prof.push_call(call, ix.pc());
        }
        // Keep here the last non-call line to process further
    }

    if prof.ground.depth() > 0 {
        tracing::warn!("Unbalanced call/exit: {}", &prof.ground.depth());
        for _ in 0..prof.ground.depth() {
            prof.pop_call();
        }
    }

    Ok(())
}
