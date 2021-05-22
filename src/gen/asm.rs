//! bpf-profile asm module.

/// Represents generated assembly file.
#[derive(Debug)]
pub struct Source {
    lines: Vec<String>,
}

use super::Result;
use std::io::Write;

impl Source {
    /// Creates new instance of Source.
    pub fn new() -> Self {
        Source { lines: Vec::new() }
    }

    /// Adds new instruction to the listing.
    pub fn add_instruction(&mut self, index: usize, text: &str) {
        if index >= self.lines.len() {
            self.lines.resize(index + 1, String::default());
        }
        let generated = format!("{}:\t\t {}", index + 1, text);
        if self.lines[index].is_empty() {
            self.lines[index] = generated;
        } else if !self.lines[index].starts_with(&generated) {
            panic!(
                "Inconsistent input: expected '{}', got '{}'",
                &self.lines[index], &generated
            );
        }
    }

    /// Writes all lines of the listing to a file.
    pub fn write(&self, mut output: impl Write) -> Result<()> {
        for line in &self.lines {
            writeln!(output, "{}", line)?;
        }
        output.flush()?;
        Ok(())
    }
}
