//! bpf-profile error module.

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

    #[error("Unsupported format of dump file: should contain standard header")]
    DumpFormat,
    #[error("Dump file without disassembly")]
    DumpFormatNoDisasm,
    #[error("Cannot parse instruction '{0}' of a function at line '{1}'")]
    DumpParsing(String, usize),

    #[error("Unsupported format of trace file: should contain standard header")]
    TraceFormat,
    #[error("Skipped input")]
    TraceSkipped,
    #[error("Instruction at line {1} is not a call: '{0}'")]
    TraceNotCall(String, usize),
    #[error("Cannot parse trace instruction '{0}' at line {1}")]
    TraceParsing(String, usize),
}

/// Represents results.
pub type Result<T> = std::result::Result<T, Error>;
