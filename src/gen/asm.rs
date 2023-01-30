//! bpf-profile-generate asm module.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::{filebuf, global};
use crate::bpf::Instruction;
use crate::error::Result;
use crate::PADDING;
use crate::resolver::Resolver;

/// Represents generated assembly file.
#[derive(Debug)]
pub struct Source {
    output_path: PathBuf,
    ixs: Vec<Instruction>,
}

impl Source {
    /// Creates new instance of Source.
    pub fn new(output_path: &Path) -> Self {
        Source {
            output_path: output_path.into(),
            ixs: Vec::new(),
        }
    }

    /// Adds new instruction to the listing.
    pub fn add_instruction(&mut self, ix: &Instruction) {
        let index = ix.pc() - 1;
        if index >= self.ixs.len() {
            self.ixs.resize(index + 1, Instruction::default());
        }
        if self.ixs[index].is_empty() {
            self.ixs[index] = ix.clone();
        } else if !self.ixs[index].compare_asm(ix) {
            panic!(
                "Inconsistent input: expected '{:?}', got '{:?}'",
                &self.ixs[index], &ix
            );
        }
    }

    /// Writes all lines of the listing to a file.
    pub fn write(&self, resv: &Resolver) -> Result<()> {
        if global::verbose() {
            tracing::info!("Writing assembly file...")
        }
        let output = filebuf::open_w(&self.output_path)?;
        if resv.is_default() {
            write_assembly_from_trace(output, &self.ixs, resv)?;
        } else {
            resv.write_pretty_source(output)?;
        }
        Ok(())
    }

    pub fn output_path(&self) -> &PathBuf {
        &self.output_path
    }
}

/// Writes all lines of the listing to a file.
/// Uses assembly instructions from the trace file.
fn write_assembly_from_trace(
    mut output: impl Write,
    ixs: &[Instruction],
    resv: &Resolver,
) -> Result<()> {
    for (i, ix) in ixs.iter().enumerate() {
        if ix.is_empty() {
            if i > 0 {
                writeln!(output)?;
            } else {
                writeln!(output, ";; Generated BPF assembly code for QCacheGrind")?;
            }
            continue;
        }

        let comment = match resv.resolve_by_first_pc(ix.pc()) {
            None => String::default(),
            Some(name) => format!("{}; {}", PADDING, &name),
        };

        if !ix.is_call() {
            writeln!(output, "{}{}", ix, comment)?;
        } else {
            let op = ix.call_operation(i)?;
            let address = ix.call_target(i)?;
            let name = resv.resolve_by_address(address);
            let ix = Instruction::new(
                ix.pc(),
                ix.data(),
                format!("{} {}", &op, &name),
                ix.units(),
            );
            writeln!(output, "{}{}", ix, comment)?;
        }
    }

    output.flush()?;
    Ok(())
}
