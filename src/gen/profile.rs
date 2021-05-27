//! bpf-profile-generate profile module.

use crate::config::{Address, Cost, Map, ProgramCounter};
use std::collections::BTreeMap;

pub type Functions = Map<Address, Function>;
type Costs = BTreeMap<ProgramCounter, Cost>; // sort by pc

/// Represents a function which will be dumped into a profile.
#[derive(Debug)]
pub struct Function {
    address: Address,
    name: String,
    costs: Costs,
    calls: Vec<Call>,
}

use crate::config::GROUND_ZERO;
use crate::resolver::Resolver;

impl Function {
    /// Creates initial function object which stores total cost of entire program.
    pub fn ground_zero() -> Self {
        Function {
            address: GROUND_ZERO,
            name: "GROUND_ZERO".into(),
            costs: BTreeMap::new(),
            calls: Vec::new(),
        }
    }

    /// Creates new function object.
    pub fn new(address: Address, first_pc: ProgramCounter, resolver: &mut Resolver) -> Self {
        assert_ne!(address, GROUND_ZERO);
        Function {
            address,
            name: resolver.update(address, first_pc),
            costs: BTreeMap::new(),
            calls: Vec::new(),
        }
    }

    /// Returns copy of the function's name.
    pub fn name(&self) -> String {
        self.name.clone()
    }

    /// Increments the immediate cost of the function.
    pub fn increment_cost(&mut self, pc: ProgramCounter) {
        tracing::debug!("Function({}).increment_cost", self.address);
        let c = *self.costs.entry(pc).or_insert(0);
        self.costs.insert(pc, c + 1);
    }

    /// Adds finished enclosed call for this function.
    pub fn add_call(&mut self, call: Call) {
        tracing::debug!("Function({}).add_call {}", self.address, call.address);
        self.calls.push(call);
    }
}

/// Represents a function call.
#[derive(Clone, Debug)]
pub struct Call {
    address: Address,
    caller: Address,
    caller_pc: ProgramCounter,
    cost: Cost,
    callee: Box<Option<Call>>,
    depth: usize,
}

use crate::bpf::Instruction;
use crate::error::{Error, Result};

impl Call {
    /// Creates new call object.
    pub fn new(address: Address, caller_pc: ProgramCounter) -> Self {
        Call {
            address,
            caller: Address::default(), // will be found later
            caller_pc,
            cost: 0,
            callee: Box::new(None),
            depth: 0,
        }
    }

    /// Creates new call object from a trace instruction (which must be a call).
    pub fn from(ix: &Instruction, lc: usize) -> Result<Self> {
        let text = ix.text();
        if !ix.is_call() {
            return Err(Error::TraceNotCall(text, lc));
        }
        let address = ix.extract_call_target(lc)?;
        Ok(Call::new(address, ix.pc()))
    }

    /// Returns address of the call.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Checks if the call is the root ("ground zero").
    pub fn is_ground(&self) -> bool {
        self.address == GROUND_ZERO
    }

    /// Returns address of the caller.
    pub fn caller(&self) -> Address {
        self.caller
    }

    /// Returns depth of enclosed callees.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Increments the cost of this call.
    pub fn increment_cost(&mut self, pc: ProgramCounter, functions: &mut Functions) {
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
    pub fn push_call(&mut self, mut call: Call) {
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
    pub fn pop_call(&mut self) -> Call {
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

use std::io::Write;

/// Writes information about calls of functions and their costs.
pub fn write_callgrind_functions(
    mut output: impl Write,
    functions: &Functions,
    line_by_line_profile_enabled: bool,
) -> Result<()> {
    // Collapse possible calls of functions from different pcs
    // in case line_by_line_profile_enabled == false
    let mut addresses = Map::new();

    // Collect (caller-pc, function-address) => (number-of-calls, inclusive-cost)
    let mut statistics = Map::new();

    for (a, f) in functions {
        if *a == GROUND_ZERO {
            continue;
        }

        // Dump costs of current function
        writeln!(output, "\nfn={}", f.name())?;
        if line_by_line_profile_enabled {
            for (pc, cost) in &f.costs {
                writeln!(output, "{} {}", pc, cost)?;
            }
        } else {
            let first_pc = f.costs.iter().next().expect("Empty function").0;
            let total_cost = f.costs.values().sum::<Cost>();
            writeln!(output, "{} {}", first_pc, total_cost)?;
        }

        // Collect statistics of callees
        addresses.clear();
        statistics.clear();
        for c in &f.calls {
            let key = if line_by_line_profile_enabled {
                (c.caller_pc, c.address)
            } else {
                let pc = addresses.entry(c.address).or_insert(c.caller_pc);
                let unified_caller_pc = *pc;
                (unified_caller_pc, c.address)
            };
            let stat = statistics.entry(key).or_insert((0_usize, 0_usize));
            let number_of_calls = stat.0 + 1;
            let inclusive_cost = stat.1 + c.cost;
            statistics.insert(key, (number_of_calls, inclusive_cost));
        }

        // Finally dump the statistics
        for ((pc, address), (number_of_calls, inclusive_cost)) in &statistics {
            writeln!(output, "cfn={}", functions[address].name)?;
            writeln!(output, "calls={} 0x{:x}", number_of_calls, address)?;
            writeln!(output, "{} {}", pc, inclusive_cost)?;
        }
    }

    output.flush()?;
    Ok(())
}
