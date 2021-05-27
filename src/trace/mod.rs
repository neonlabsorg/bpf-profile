//! bpf-profile trace command implementation.

use crate::error::Result;
use std::path::Path;

/// Reads the trace input file and prints functions in order of calls.
pub fn run(_trace_path: &Path) -> Result<()> {
    Ok(())
}
