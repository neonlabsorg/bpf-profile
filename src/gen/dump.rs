//! bpf-profile dump module.

use super::{fileutil, Error, Result};
use crate::config::{Address, Map, Set, GROUND_ZERO};
use lazy_static::lazy_static;
use regex::Regex;
use std::cell::{Cell, RefCell};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

/// Reads the dump file (if any) and returns a dump representation.
pub fn read(filename: Option<PathBuf>) -> Result<Resolver> {
    match filename {
        None => Ok(Resolver::default()),
        Some(filename) => Resolver::read(&filename),
    }
}

/// Represents the dumpfile contents.
#[derive(Default, Debug)]
pub struct Resolver {
    counter: Cell<usize>,
    names: RefCell<Map<Address, String>>,
}

const PREFIX_OF_UNRESOLVED: &str = "function_";

impl Resolver {
    /// Returns new empty instance of the dump object.
    fn read(filename: &Path) -> Result<Self> {
        let mut resolver = Resolver::default();
        let reader = BufReader::new(fileutil::open(filename)?);
        parse_dump_file(reader, &mut resolver)?;
        Ok(resolver)
    }

    /// Takes an address and returns name of corresponding function,
    /// otherwise returns a generated string if can not resolve properly.
    pub fn resolve(&self, address: Address) -> String {
        if address == GROUND_ZERO {
            "GROUND_ZERO".into() // shouldn't appear in output
        } else {
            self.names
                .borrow_mut()
                .entry(address)
                .or_insert_with(|| {
                    let index = self.counter.get();
                    self.counter.set(index + 1);
                    format!("{}{}", PREFIX_OF_UNRESOLVED, index)
                })
                .to_string()
        }
    }
}

const HEADER: &str = "ELF Header";
const SYMTAB_HEADER: &str = "Symbol table '.symtab'";
const DISASM_HEADER: &str = "Disassembly of section .text";

/// Parses the dump file building the Resolver instance.
fn parse_dump_file(mut reader: impl BufRead, _dump: &mut Resolver) -> Result<()> {
    // reuse string in the loop for better performance
    let mut line = String::with_capacity(512);
    let mut bytes_read = usize::MAX;

    // Skip to the symtab
    let mut was_header = false;
    let mut was_symtab = false;
    while bytes_read != 0 {
        line.clear();
        bytes_read = reader
            .read_line(&mut line)
            .map_err(|e| Error::ReadLine(e, line.clone()))?;
        if line.starts_with(HEADER) {
            was_header = true;
            continue;
        }
        if line.starts_with(SYMTAB_HEADER) {
            if !was_header {
                return Err(Error::DumpFormat);
            }
            was_symtab = true;
            break;
        }
    }
    if !was_symtab {
        return Ok(()); // just useless dump
    }

    lazy_static! {
        static ref FUNC: Regex =
            Regex::new(r"\s+\d+\s+[[:xdigit:]]+\s+\d+\s+FUNC\s+LOCAL\s+HIDDEN\s+\d+\s+(.+)")
                .expect("Invalid regex");
    }

    // Read the symtab
    let mut func_names = Set::new();
    while bytes_read != 0 {
        line.clear();
        bytes_read = reader
            .read_line(&mut line)
            .map_err(|e| Error::ReadLine(e, line.clone()))?;
        if line.trim().is_empty() {
            break;
        }
        if let Some(caps) = FUNC.captures(&line) {
            let name = caps[1].to_string();
            func_names.insert(name);
        }
    }
    if func_names.is_empty() {
        return Ok(()); // just useless dump
    }

    // Skip to the disassembly
    let mut was_disasm = false;
    while bytes_read != 0 {
        line.clear();
        bytes_read = reader
            .read_line(&mut line)
            .map_err(|e| Error::ReadLine(e, line.clone()))?;
        if line.starts_with(DISASM_HEADER) {
            was_disasm = true;
            break;
        }
    }
    if !was_disasm {
        return Err(Error::DumpFormatNoDisasm);
    }

    lazy_static! {
        static ref FUNC_HEADER: Regex =
            Regex::new(r"[[:xdigit:]]+\s+<(.+)>").expect("Invalid regex");
    }

    // Read functions
    while bytes_read != 0 {
        line.clear();
        bytes_read = reader
            .read_line(&mut line)
            .map_err(|e| Error::ReadLine(e, line.clone()))?;
        if let Some(caps) = FUNC_HEADER.captures(&line) {
            let name = caps[1].to_string();
            if func_names.contains(&name) {
                println!("{}", &name);
            }
        }
    }

    Ok(())
}

// Represents a function.
//struct Function {
//    name: String,
//}
