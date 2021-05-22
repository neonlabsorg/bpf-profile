//! bpf-profile implementation of the profile struct.

use super::{asm, fileutil, Error, Result};
use crate::config::{Address, Cost, Map, ProgramCounter, GROUND_ZERO};
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

type Functions = Map<Address, Function>;
type Costs = BTreeMap<ProgramCounter, Cost>; // sort by pc

/// Checks the trace file contains expected header line.
pub fn contains_standard_header(mut reader: impl BufRead) -> Result<bool> {
    lazy_static! {
        static ref TRACE_HEADER: Regex =
            Regex::new(r"\[.+\s+TRACE\s+.+BPF Program Instruction Trace").expect("Invalid regex");
    }

    let mut line = String::with_capacity(512);
    let mut bytes_read = usize::MAX;

    while bytes_read != 0 {
        bytes_read = fileutil::read_line(&mut reader, &mut line)?;
        if TRACE_HEADER.is_match(&line) {
            return Ok(true);
        }
    }

    Ok(false)
}

use super::dump::{self, Resolver};

/// Represents the profile.
#[derive(Debug)]
pub struct Profile {
    total_cost: Cost,
    ground: Call,
    functions: Functions,
    dump: Resolver,
    asm: asm::Source,
}

impl Profile {
    /// Creates the initial instance of profile.
    pub fn new(dump: Resolver) -> Result<Self> {
        let mut functions = Map::new();
        functions.insert(GROUND_ZERO, Function::ground_zero());
        Ok(Profile {
            total_cost: 0,
            ground: Call::new(GROUND_ZERO),
            functions,
            dump,
            asm: asm::Source::new(),
        })
    }

    /// Reads the trace and creates the profile data.
    pub fn create(trace_path: &Path, dump_path: Option<&Path>) -> Result<Self> {
        tracing::debug!("Profile.create {:?}", trace_path);

        /*let source_path = match dump_path {
            None => trace_path,
            Some(dump_path) => dump_path,
        };
        let source_filename = source_path
            .to_str()
            .ok_or_else(|| Error::Filename(source_path.into()))?
            .to_string();*/

        let dump = dump::read(dump_path)?;
        let reader = BufReader::new(fileutil::open(&trace_path)?);
        let mut prof = Profile::new(dump)?;
        parse(reader, &mut prof)?;

        Ok(prof)
    }

    /// Writes the generated assembly file.
    pub fn write_asm(&self, asm_path: &Path) -> Result<()> {
        let output = fileutil::open_w(asm_path)?;
        self.asm.write(output)
    }

    /// Writes the profile data in the callgrind file format.
    /// See details of the format in the Valgrind documentation.
    pub fn write_callgrind(&self, mut output: impl Write, asm_fl: &str) -> Result<()> {
        writeln!(output, "# callgrind format")?;
        writeln!(output, "version: 1")?;
        writeln!(output, "creator: bpf-profile")?;
        writeln!(output, "events: Instructions")?;
        writeln!(output, "totals: {}", self.total_cost)?;
        writeln!(output, "fl={}", asm_fl)?;
        write_callgrind_functions(&self.functions, output)?;
        Ok(())
    }

    /// Adds instruction to the generated assembly listing.
    fn keep_asm(&mut self, ix: &Instruction) {
        self.asm.add_instruction(ix.pc, &ix.text);
    }

    /// Increments the total cost and the cost of current call.
    fn increment_cost(&mut self, pc: ProgramCounter) {
        tracing::debug!("Profile.increment_cost");
        self.total_cost += 1;
        self.ground.increment_cost(pc, &mut self.functions);
    }

    /// Adds next call to the call stack.
    fn push_call(&mut self, call: Call, first_pc: ProgramCounter) {
        let address = call.address;
        tracing::debug!("Profile.push_call {}", address);
        self.ground.push_call(call);
        #[allow(clippy::map_entry)]
        if !self.functions.contains_key(&address) {
            tracing::debug!("Add function to the registry: {}", address);
            let func = Function::new(address, first_pc, &mut self.dump);
            self.functions.insert(address, func);
        }
    }

    /// Removes finished call from the call stack and adds it to the caller.
    fn pop_call(&mut self) {
        let call = self.ground.pop_call();
        tracing::debug!("Profile.pop_call {}", &call.address);
        if !call.is_ground() {
            let f = self
                .functions
                .get_mut(&call.caller)
                .expect("Caller not found in registry of functions");
            f.add_call(call);
        }
    }
}

/// Represents a function call.
#[derive(Clone, Debug)]
struct Call {
    address: Address,
    caller: Address,
    cost: Cost,
    callee: Box<Option<Call>>,
    depth: usize,
}

impl Call {
    /// Creates new call object.
    fn new(address: Address) -> Self {
        Call {
            address,
            caller: Address::default(),
            cost: 0,
            callee: Box::new(None),
            depth: 0,
        }
    }

    /// Creates new call object from a trace instruction (which must be a call).
    fn from(ix: &Instruction, lc: usize) -> Result<Self> {
        let text = ix.text();
        if !ix.is_call() {
            return Err(Error::TraceNotCall(text));
        }
        let mut pair = text.split_whitespace(); // => "call something"
        let _ = pair
            .next()
            .ok_or_else(|| Error::TraceParsing(ix.text(), lc))?;
        let address = pair
            .next()
            .ok_or_else(|| Error::TraceParsing(ix.text(), lc))?;
        Ok(Call::new(hex_str_to_address(address)))
    }

    /// Checks if the call is the root ("ground zero").
    fn is_ground(&self) -> bool {
        self.address == GROUND_ZERO
    }

    /// Increments the cost of this call.
    fn increment_cost(&mut self, pc: ProgramCounter, functions: &mut Functions) {
        tracing::debug!("Call({}).increment_cost", self.address);
        match *self.callee {
            Some(ref mut callee) => {
                callee.increment_cost(pc, functions);
            }
            None => {
                self.cost += 1;
                let f = functions
                    .get_mut(&self.address)
                    .expect("Call address not found in the registry of functions");
                f.increment_cost(pc);
            }
        }
    }

    /// Adds next call to the call stack.
    fn push_call(&mut self, mut call: Call) {
        tracing::debug!(
            "Call({}).push_call {} depth={}",
            self.address,
            call.address,
            self.depth
        );
        self.depth += 1;
        match *self.callee {
            Some(ref mut callee) => {
                callee.push_call(call);
            }
            None => {
                call.caller = self.address;
                let old = std::mem::replace(&mut *self.callee, Some(call));
                assert!(old.is_none());
            }
        }
    }

    /// Removes current call from the call stack.
    fn pop_call(&mut self) -> Call {
        tracing::debug!("Call({}).pop_call depth={}", self.address, self.depth);
        if self.depth == 0 {
            panic!("Exit without call");
        }
        self.depth -= 1;
        let callee = self.callee.as_mut().as_mut().expect("Missing callee");
        if callee.callee.is_some() {
            callee.pop_call()
        } else {
            let call = self.callee.take().expect("Missing callee");
            self.cost += call.cost;
            call
        }
    }
}

/// Represents a function which will be dumped into a profile.
#[derive(Debug)]
struct Function {
    address: Address,
    name: String,
    entry: ProgramCounter,
    costs: Costs,
    calls: Vec<Call>,
}

impl Function {
    /// Creates initial function object which stores total cost of entire program.
    fn ground_zero() -> Self {
        Function {
            address: GROUND_ZERO,
            name: "GROUND_ZERO".into(),
            entry: 0,
            costs: BTreeMap::new(),
            calls: Vec::new(),
        }
    }

    /// Creates new function object.
    fn new(address: Address, first_pc: ProgramCounter, dump: &mut Resolver) -> Self {
        assert_ne!(address, GROUND_ZERO);
        Function {
            address,
            name: dump.resolve(address, first_pc),
            entry: first_pc,
            costs: BTreeMap::new(),
            calls: Vec::new(),
        }
    }

    /// Increments the immediate cost of the function.
    fn increment_cost(&mut self, pc: ProgramCounter) {
        tracing::debug!("Function({}).increment_cost", self.address);
        let c = *self.costs.entry(pc).or_insert(0);
        self.costs.insert(pc, c + 1);
    }

    /// Adds finished enclosed call for this function.
    fn add_call(&mut self, call: Call) {
        tracing::debug!("Function({}).add_call {}", self.address, call.address);
        self.calls.push(call);
    }
}

/// Represents trace instruction (call or another).
#[derive(Debug)]
struct Instruction {
    pc: ProgramCounter,
    text: String,
}

impl Instruction {
    /// Parses the input string and creates corresponding instruction if possible.
    fn parse(s: &str) -> Result<Self> {
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
    fn text(&self) -> String {
        self.text.clone()
    }

    /// Returns program counter of the instruction.
    fn pc(&self) -> ProgramCounter {
        self.pc
    }

    /// Checks if the instruction is a call of function.
    fn is_call(&self) -> bool {
        self.text.starts_with("call")
    }

    /// Checks if the instruction is exit of function.
    fn is_exit(&self) -> bool {
        self.text == "exit"
    }
}

/// Parses the trace file line by line building the Profile instance.
pub fn parse(mut reader: impl BufRead, prof: &mut Profile) -> Result<()> {
    let mut line = String::with_capacity(512);
    let mut bytes_read = usize::MAX;
    let mut lc = 0_usize;
    let mut ix: Instruction;

    while bytes_read != 0 {
        if line.is_empty() {
            bytes_read = fileutil::read_line(&mut reader, &mut line)?;
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
            bytes_read = fileutil::read_line(&mut reader, &mut line)?;
            lc += 1;
            ix = Instruction::parse(&line)?;
            prof.push_call(call, ix.pc());
        }
        // Keep here the last non-call line to process further
    }

    if prof.ground.depth > 0 {
        tracing::warn!("Unbalanced call/exit: {}", &prof.ground.depth);
        for _ in 0..prof.ground.depth {
            prof.pop_call();
        }
    }
    Ok(())
}

/// Writes information about calls of functions and their costs.
fn write_callgrind_functions(functions: &Functions, mut output: impl Write) -> Result<()> {
    let mut statistics = Map::new();

    for (a, f) in functions {
        if *a == GROUND_ZERO {
            continue;
        }

        writeln!(output)?;
        writeln!(output, "fn={}", f.name)?;
        for (pc, cost) in &f.costs {
            writeln!(output, "{} {}", pc, cost)?;
        }

        statistics.clear();
        for c in &f.calls {
            let stat = statistics.entry(&c.address).or_insert((0_usize, 0_usize));
            let number_of_calls = stat.0 + 1;
            let inclusive_cost = stat.1 + c.cost;
            statistics.insert(&c.address, (number_of_calls, inclusive_cost));
        }
        for (a, s) in &statistics {
            writeln!(output, "cfn={}", functions[a].name)?;
            writeln!(output, "calls={} 0x{:x}", s.0, a)?;
            writeln!(output, "{} {}", f.entry, s.1)?;
        }
    }

    output.flush()?;
    Ok(())
}

/// Converts a hex number string representation to integer Address.
fn hex_str_to_address(s: &str) -> Address {
    let a = s.trim_start_matches("0x");
    Address::from_str_radix(a, 16).expect("Invalid address")
}
