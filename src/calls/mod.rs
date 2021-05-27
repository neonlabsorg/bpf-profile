//! bpf-profile calls command implementation.

use crate::error::{Error, Result};
use crate::filebuf;
use std::path::Path;

/// Reads the trace input file and prints functions in order of calls.
pub fn run(trace_path: &Path, dump_path: Option<&Path>, tab: usize) -> Result<()> {
    if !crate::trace::contains_standard_header(filebuf::open(&trace_path)?)? {
        return Err(Error::TraceFormat);
    }

    let mut resolv = crate::resolver::read(dump_path)?;
    {
        let reader = filebuf::open(&trace_path)?;
        update_resolver(reader, &mut resolv)?;
    }

    let reader = filebuf::open(&trace_path)?;
    parse(reader, &resolv, tab)?;

    Ok(())
}

use crate::bpf::Instruction;
use crate::resolver::Resolver;
use std::io::BufRead;

/// Parses the trace file line by line updating the resolver.
fn update_resolver(mut reader: impl BufRead, resolv: &mut Resolver) -> Result<()> {
    let mut line = String::with_capacity(512);
    let mut bytes_read = usize::MAX;
    let mut ix: Instruction;
    let mut lc = 0_usize;

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

        if !ix.is_call() {
            line.clear();
            continue;
        }

        // Handle sequences of enclosed calls as well:
        // 604: call 0xcb3fc071
        // 588: call 0x8e0001f9
        // 1024: call 0x8bf38212
        // ...
        while ix.is_call() {
            let address = ix.extract_call_target(lc)?;
            // Read next line — the first instruction of the call
            bytes_read = filebuf::read_line(&mut reader, &mut line)?;
            lc += 1;
            ix = Instruction::parse(&line)?;
            resolv.update(address, ix.pc());
        }
        // Keep here the last non-call line to process further
    }

    Ok(())
}

/// Parses the trace file line by line printing calls.
fn parse(mut reader: impl BufRead, resolv: &Resolver, tab: usize) -> Result<()> {
    let mut depth = 0_usize;
    let mut line = String::with_capacity(512);
    let mut bytes_read = usize::MAX;
    let mut ix: Instruction;
    let mut lc = 0_usize;

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

        if !ix.is_call() {
            if ix.is_exit() {
                depth -= 1;
            }
            line.clear();
            continue;
        }

        // Handle sequences of enclosed calls as well:
        // 604: call 0xcb3fc071
        // 588: call 0x8e0001f9
        // 1024: call 0x8bf38212
        // ...
        while ix.is_call() {
            let address = ix.extract_call_target(lc)?;
            let name = resolv.resolve_by_address(address);
            println!(
                "{:indent$}{}",
                String::default(),
                &name,
                indent = depth * tab
            );
            depth += 1;
            // Read next line — the first instruction of the call
            bytes_read = filebuf::read_line(&mut reader, &mut line)?;
            lc += 1;
            ix = Instruction::parse(&line)?;
        }
        // Keep here the last non-call line to process further
    }

    Ok(())
}
