//! bpf-profile generate command implementation.

use std::io;
use std::path::Path;

use trace::Profile;

use crate::DEFAULT_ASM;
use crate::error::{Error, Result};
use crate::filebuf;

mod asm;
mod profile;
mod trace;

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

    let source_filename = match asm_path {
        None => DEFAULT_ASM,
        Some(asm_path) => asm_path
            .to_str()
            .ok_or_else(|| Error::Filename(asm_path.into()))?,
    };

    match output_path {
        None => profile.write_callgrind(io::stdout(), source_filename),
        Some(output_path) => {
            let output = filebuf::open_w(output_path)?;
            profile.write_callgrind(output, source_filename)
        }
    }
}
