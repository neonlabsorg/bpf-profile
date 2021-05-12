//! bpf_profile main module.
//!
//! This program reads a trace file that contains the trace output of the BPF VM.
//! and generates a profile for tools like `callgrind_annotate` or `qcachegrind`.
//!
//! To resolve names of functions this program may require a dump file containing
//! the instruction dump of the ELF.
//!
//! You can create the dump file by passing the --dump flag to `cargo build-bpf`,
//! or directly:
//!     `llvm-objdump -print-imm-hex --source --disassemble <ELF file path>`
//!
//! You can create the trace file by running the Solana cluster under `RUST_LOG`:
//!     `export RUST_LOG=solana_rbpf=trace`

#![forbid(unsafe_code)]
#![deny(warnings)]

mod cli;
mod config;
mod gen;
mod tests;

fn main() {
    init_logger();
    if let Err(err) = execute(cli::application()) {
        eprintln!("Error: {:#}", err);
        std::process::exit(config::FAILURE);
    }
}

/// Initializes the logger.
fn init_logger() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    tracing_subscriber::fmt::init();
}

/// Dispatches CLI commands.
fn execute(app: cli::Application) -> gen::Result<()> {
    match app.cmd {
        cli::Command::Generate {
            trace,
            dump,
            output,
            format,
        } => {
            gen::run(trace, dump, output, format)?;
        }
    }

    Ok(())
}
