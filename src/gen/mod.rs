//! bpf-profile generate command implementation.

mod dump;
mod fileutil;
mod trace;

#[cfg(test)]
mod tests;

use std::io;
use std::path::PathBuf;

/// Represents errors of the converter.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Unsupported file name '{0}'")]
    Filename(PathBuf),

    #[error("Cannot open file '{1}': {0}")]
    OpenFile(#[source] io::Error, PathBuf),
    #[error("Cannot read line '{1}': {0}")]
    ReadLine(#[source] io::Error, String),
    #[error("Input/output error: {0}")]
    Io(#[from] io::Error),

    #[error("Unsupported format of dump file")]
    DumpFormat,
    #[error("Dump file without disassembly")]
    DumpFormatNoDisasm,
    #[error("Cannot parse instruction '{0}' of a function at line '{1}'")]
    DumpParsing(String, usize),

    #[error("Unsupported format of trace file")]
    TraceFormat,
    #[error("Skipped input")]
    TraceSkipped,
    #[error("Instruction is not a call: '{0}'")]
    TraceNotCall(String),
    #[error("Cannot parse trace instruction '{0}' at line {1}")]
    TraceParsing(String, usize),
}

/// Represents results.
pub type Result<T> = std::result::Result<T, Error>;

use std::io::{BufReader, BufWriter};
use std::path::Path;
use trace::Profile;

/// Runs the conversion from trace to a profiler output.
pub fn run(
    trace_path: &Path,
    dump_path: Option<&Path>,
    output_path: Option<&Path>,
    _: &str, // always 'callgrind' currently
) -> Result<()> {
    if !trace::contains_standard_header(BufReader::new(fileutil::open(&trace_path)?))? {
        return Err(Error::TraceFormat);
    }

    let profile = Profile::create(trace_path, dump_path)?;

    match output_path {
        None => profile.write_callgrind(io::stdout()),
        Some(output_path) => {
            let output = fileutil::open_w(&output_path)?;
            profile.write_callgrind(BufWriter::new(output))
        }
    }
}
