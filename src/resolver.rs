//! bpf-profile resolver module.

use crate::config::{Address, Index, Map, ProgramCounter, GROUND_ZERO, PADDING};
use crate::error::{Error, Result};
use crate::{filebuf, global};
use std::io::{BufRead, Write};
use std::path::Path;

/// Reads the dump file (if any) and returns a dump representation.
pub fn read(filepath: Option<&Path>) -> Result<Resolver> {
    match filepath {
        None => Ok(Resolver::default()),
        Some(path) => Resolver::read(path),
    }
}

/// Represents the dump file contents.
#[derive(Default, Debug)]
pub struct Resolver {
    not_default: bool,
    functions: Vec<String>,
    index_function_by_address: Map<Address, Index>,
    index_function_by_first_pc: Map<ProgramCounter, Index>,
    unresolved_counter: usize,
    pretty_source: Vec<String>,
}

const PREFIX_OF_UNRESOLVED: &str = "function_";

impl Resolver {
    /// Reads the dump file to collect function names and pretty assembly.
    /// Returns non-trivial (with real function names) instance of the Resolver.
    fn read(filepath: &Path) -> Result<Self> {
        if global::verbose() {
            tracing::info!("Reading dump file, creating resolver...")
        }
        let mut resv = Resolver::default();
        let reader = filebuf::open(filepath)?;
        parse_dump_file(reader, &mut resv)?;
        resv.not_default = true;
        Ok(resv)
    }

    /// Checks if resolver was generated from nothing (default) or from the dump file.
    pub fn is_default(&self) -> bool {
        !self.not_default
    }

    /// Takes an address and returns name of corresponding function.
    pub fn resolve_by_address(&self, address: Address) -> String {
        tracing::debug!("Resolver.resolve(0x{:x})", &address);
        assert_ne!(address, GROUND_ZERO);
        let func_index = self.index_function_by_address[&address];
        let func_name = self.functions[func_index].clone();
        tracing::debug!("Resolver.resolve returns {})", &func_name);
        func_name
    }

    /// Takes a program counter and returns name of function which begins with it (if any).
    pub fn resolve_by_first_pc(&self, pc: ProgramCounter) -> Option<String> {
        let func_index = self.index_function_by_first_pc.get(&pc);
        func_index.map(|i| self.functions[*i].clone())
    }

    /// Takes an address and returns name of corresponding function,
    /// otherwise returns a generated string if can not resolve properly.
    pub fn update(&mut self, address: Address, first_pc: ProgramCounter) -> String {
        tracing::debug!("Resolver.update(0x{:x}, {})", &address, &first_pc);
        assert_ne!(address, GROUND_ZERO);

        let found = self.index_function_by_address.contains_key(&address);
        if !found {
            if self.contains_function_with_first_pc(first_pc) {
                // There can be multiple copies of one function with different addresses
                let func_index = self.index_function_by_first_pc[&first_pc];
                self.index_function_by_address.insert(address, func_index);
            } else {
                let unresolved_func_name = format!(
                    "{}{} (0x{:x})",
                    PREFIX_OF_UNRESOLVED, self.unresolved_counter, address
                );
                self.unresolved_counter += 1;
                let func_index = self.update_first_pc_index(&unresolved_func_name, first_pc);
                self.index_function_by_address.insert(address, func_index);
            }
        }

        let func_index = self.index_function_by_address[&address];
        let func_name = self.functions[func_index].clone();
        tracing::debug!("Resolver.update returns {})", &func_name);
        func_name
    }

    /// Writes source lines from dump file (if any) into the output.
    pub fn write_pretty_source(&self, mut output: impl Write) -> Result<()> {
        writeln!(
            output,
            ";; Generated BPF pretty assembly code for QCacheGrind"
        )?;
        for i in 2..self.pretty_source.len() {
            if !self.contains_function_with_first_pc(i) {
                writeln!(output, "{}", &self.pretty_source[i])?;
            } else {
                let function = self.resolve_by_first_pc(i).unwrap();
                writeln!(
                    output,
                    "{}{}; {}",
                    &self.pretty_source[i], PADDING, function
                )?;
            }
        }
        output.flush()?;
        Ok(())
    }

    /// Checks if a function has been indexed already.
    fn contains_function_with_first_pc(&self, first_pc: ProgramCounter) -> bool {
        self.index_function_by_first_pc.contains_key(&first_pc)
    }

    /// Creates new entry in the index of functions by their first instruction's pc.
    fn update_first_pc_index(&mut self, name: &str, first_pc: ProgramCounter) -> Index {
        let func_index = self.functions.len();
        self.functions.push(name.into());
        self.index_function_by_first_pc.insert(first_pc, func_index);
        func_index
    }

    /// Adds new line to the pretty source listing.
    fn add_pretty_source(&mut self, i: usize, s: String) {
        if i >= self.pretty_source.len() {
            self.pretty_source.resize(i + 1, String::default());
        }
        self.pretty_source[i] = s;
    }

    fn compress(&mut self) {
        self.functions.shrink_to_fit();
        self.pretty_source.shrink_to_fit();
    }
}

use lazy_static::lazy_static;
use regex::Regex;

const HEADER: &str = "ELF Header";
const DISASM_HEADER: &str = "Disassembly of section .text";

/// Parses the dump file building the Resolver instance.
fn parse_dump_file(mut reader: impl BufRead, resv: &mut Resolver) -> Result<()> {
    let mut line = String::with_capacity(512);
    let mut bytes_read = usize::MAX;
    let mut lc = 0_usize;

    // Skip to the disassembly
    let mut was_header = false;
    let mut was_disasm = false;
    while bytes_read != 0 {
        bytes_read = filebuf::read_line(&mut reader, &mut line)?;
        lc += 1;
        if line.starts_with(HEADER) {
            was_header = true;
            continue;
        }
        if line.starts_with(DISASM_HEADER) {
            if !was_header {
                return Err(Error::DumpFormat);
            }
            was_disasm = true;
            break;
        }
    }
    if !was_disasm {
        return Err(Error::DumpFormatNoDisasm);
    }

    lazy_static! {
        static ref LBB: Regex = Regex::new(r"^[[:xdigit:]]+\s+<(LBB.+)>").expect("Invalid regex");
        static ref FUNC_HEADER: Regex =
            Regex::new(r"^[[:xdigit:]]+\s+<(.+)>").expect("Invalid regex");
        static ref INSTRUCTION: Regex =
            Regex::new(r"^\s+(\d+)(\s+[[:xdigit:]]{2})+\s+(.+)").expect("Invalid regex");
    }

    // Read functions and their instructions
    let mut label = String::new();
    let mut function = String::new();
    while bytes_read != 0 {
        bytes_read = filebuf::read_line(&mut reader, &mut line)?;
        lc += 1;

        if line.trim().is_empty() {
            continue;
        }

        if let Some(caps) = LBB.captures(&line) {
            assert!(label.is_empty());
            label = caps[1].to_string();
        } else if let Some(caps) = FUNC_HEADER.captures(&line) {
            assert!(function.is_empty());
            function = caps[1].to_string();
        } else if let Some(caps) = INSTRUCTION.captures(&line) {
            let pc = caps[1]
                .parse::<ProgramCounter>()
                .expect("Cannot parse program counter");
            let text = caps[3].to_string();
            if !function.is_empty() {
                if !resv.contains_function_with_first_pc(pc) {
                    resv.update_first_pc_index(&function, pc);
                }
                function.clear();
            }
            resv.add_pretty_source(
                pc,
                if label.is_empty() {
                    format!("{}:{}{}", pc, PADDING, &text)
                } else {
                    format!("{}:{}{}{}; {}", pc, PADDING, &text, PADDING, &label)
                },
            );
            label.clear();
        } else {
            return Err(Error::DumpParsing(line, lc));
        }
    }

    resv.compress();
    Ok(())
}
