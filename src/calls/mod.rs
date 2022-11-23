//! bpf-profile calls command implementation.

use crate::error::{Error, Result};
use crate::{filebuf, global};
use std::path::Path;

/// Reads the trace input file and prints functions in order of calls.
pub fn run(trace_path: &Path, dump_path: Option<&Path>, tab: usize) -> Result<()> {
    if !crate::trace::contains_standard_header(filebuf::open(trace_path)?)? {
        return Err(Error::TraceFormat);
    }

    let max_depth;
    let mut resv = crate::resolver::read(dump_path)?;

    {
        let reader = filebuf::open(trace_path)?;
        max_depth = update_resolver(reader, &mut resv)?;
    }

    let depth_width = max_depth.to_string().len();
    let reader = filebuf::open(trace_path)?;
    trace_calls(reader, &resv, depth_width, tab)?;

    Ok(())
}

use crate::bpf::Instruction;
use crate::resolver::Resolver;
use std::io::BufRead;

/// Parses the trace file line by line updating the resolver.
/// Returns maximal depth of enclosed function calls.
fn update_resolver(mut reader: impl BufRead, resv: &mut Resolver) -> Result<usize> {
    if global::verbose() {
        tracing::info!("First pass of trace: updating resolver...")
    }

    let mut line = String::with_capacity(512);
    let mut bytes_read = usize::MAX;
    let mut ix: Instruction;
    let mut lc = 0_usize;
    let mut depth = 0_usize;
    let mut max_depth = 0_usize;

    while bytes_read != 0 {
        if line.is_empty() {
            bytes_read = filebuf::read_line(&mut reader, &mut line)?;
            lc += 1;
        }

        let ixr = Instruction::parse(&line, lc);
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
            let address = ix.call_target(lc)?;
            depth += 1;
            max_depth = std::cmp::max(depth, max_depth);
            // Read next line — the first instruction of the call
            bytes_read = filebuf::read_line(&mut reader, &mut line)?;
            lc += 1;
            ix = Instruction::parse(&line, lc)?;
            resv.update(address, ix.pc());
        }
        // Keep here the last non-call line to process further
    }

    Ok(max_depth)
}

/// Parses the trace file line by line printing calls.
fn trace_calls(
    mut reader: impl BufRead,
    resv: &Resolver,
    depth_width: usize,
    tab: usize,
) -> Result<()> {
    if global::verbose() {
        tracing::info!("Second pass of trace: dumping functions...")
    }

    let mut line = String::with_capacity(512);
    let mut bytes_read = usize::MAX;
    let mut ix: Instruction;
    let mut lc = 0_usize;
    let mut depth = 0_usize;

    while bytes_read != 0 {
        if line.is_empty() {
            bytes_read = filebuf::read_line(&mut reader, &mut line)?;
            lc += 1;
        }

        let ixr = Instruction::parse(&line, lc);
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
            let address = ix.call_target(lc)?;
            let name = resv.resolve_by_address(address);
            println!(
                "[{:width$}] {:indent$}{}",
                depth,
                String::default(),
                &name,
                width = depth_width,
                indent = depth * tab
            );
            depth += 1;
            // Read next line — the first instruction of the call
            bytes_read = filebuf::read_line(&mut reader, &mut line)?;
            lc += 1;
            ix = Instruction::parse(&line, lc)?;
        }
        // Keep here the last non-call line to process further
    }

    Ok(())
}
