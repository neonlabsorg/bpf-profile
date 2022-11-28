//! bpf-profile-generate trace module.
//! Implements parsing of the trace file and generating the profile.

use super::asm;
use super::profile::{self, Call, Function, Functions};
use crate::{Cost, Map, ProgramCounter, GROUND_ZERO, DEFAULT_ASM};
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
    pub fn new(resolver: Resolver, asm_path: Option<&Path>) -> Result<Self> {
        let mut functions = Map::new();
        functions.insert(GROUND_ZERO, Function::ground_zero());
        Ok(Profile {
            total_cost: 0,
            ground: Call::new(GROUND_ZERO, 0),
            functions,
            resolver,
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

        let resolver = resolver::read(dump_path)?;
        let reader = filebuf::open(trace_path)?;
        let mut prof = Profile::new(resolver, asm_path)?;
        parse(reader, &mut prof)?;

        Ok(prof)
    }

    /// Writes the profile data in the callgrind file format.
    /// See details of the format in the Valgrind documentation.
    pub fn write_callgrind(&self, mut output: impl Write) -> Result<()> {
        let asm_fl = match &self.asm {
            Some(asm) => {
                asm.write(&self.resolver)?;
                asm.output_path().to_string_lossy()
            }
            None => DEFAULT_ASM.into(),
        };

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
pub fn parse(reader: impl BufRead, prof: &mut Profile) -> Result<()> {
    if global::verbose() {
        tracing::info!("Parsing trace file, creating profile...")
    }

    let mut lc = 0_usize;
    let iterator = reader.lines()
        .map(|line| {
            lc += 1;
            match line {
                Ok(line) => Instruction::parse(&line, lc).map(|ix| (lc, ix)),
                Err(err) => Err(err.into()),
            }
        });

    process(iterator, prof)
}

/// Parses the trace items one by one, building the Profile instance.
pub fn process(
    iterator: impl Iterator<Item=Result<(usize, Instruction)>>,
    prof: &mut Profile,
) -> Result<()> {
    let mut call_opt = None;
    for result in iterator {
        let (lc, ix) = match result {
            Ok((lc, ix)) => (lc, ix),
            Err(Error::TraceSkipped) => {
                /* warn!("Skip '{}'", &line.trim()); */
                continue;
            }
            Err(err) => return Err(err),
        };

        // Handle sequences of enclosed calls as well:
        // 604: call 0xcb3fc071
        // 588: call 0x8e0001f9
        // 1024: call 0x8bf38212
        // ...
        if let Some(call) = call_opt.take() {
            prof.push_call(call, ix.pc());
        }

        prof.keep_asm(&ix);
        prof.increment_cost(ix.pc());

        if ix.is_exit() {
            prof.pop_call();
        } else if ix.is_call() {
            call_opt = Some(Call::from(&ix, lc)?);
        }
    }

    assert!(call_opt.is_none());

    if prof.ground.depth() > 0 {
        tracing::warn!("Unbalanced call/exit: {}", &prof.ground.depth());
        for _ in 0..prof.ground.depth() {
            prof.pop_call();
        }
    }

    Ok(())
}
