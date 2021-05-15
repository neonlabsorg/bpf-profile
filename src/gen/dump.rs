//! bpf-profile dump module.

use super::{fileutil, Result};
use crate::config::{Address, GROUND_ZERO};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
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
    names: RefCell<HashMap<Address, String>>,
}

const PREFIX_OF_UNRESOLVED: &str = "function_";

impl Resolver {
    /// Returns new empty instance of the dump object.
    fn read(file: &Path) -> Result<Self> {
        let mut resolver = Resolver::default();
        let reader = BufReader::new(fileutil::open(file)?);
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

/// Parses the dump file building the Resolver instance.
pub fn parse_dump_file(mut _reader: impl BufRead, _dump: &mut Resolver) -> Result<()> {
    Ok(())
}
