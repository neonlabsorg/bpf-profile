//! bpf-profile generate command implementation.

use std::io;
use std::path::Path;

use trace::Profile;

use crate::error::{Error, Result};
use crate::filebuf;

pub mod trace;

mod asm;
mod profile;

#[cfg(test)]
mod tests;

/// Runs the conversion from BPF trace to a profiler output.
pub fn run(
    trace_path: &Path,
    asm_path: Option<&Path>,
    dump_path: Option<&Path>,
    _: &str, // always 'callgrind' currently
    output_path: Option<&Path>,
) -> Result<()> {
    if !crate::trace::contains_standard_header(filebuf::open(trace_path)?)? {
        return Err(Error::TraceFormat);
    }

    let profile = Profile::create(trace_path, dump_path, asm_path)?;

    match output_path {
        None => profile.write_callgrind(io::stdout(), None),
        Some(output_path) => profile.write_callgrind(filebuf::open_w(output_path)?, None),
    }
}
