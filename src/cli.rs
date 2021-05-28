//! bpf-profile command line interface definition.

use crate::config;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(about = "BPF trace to profile converter")]
pub struct Application {
    #[structopt(
         parse(from_os_str),
         short,
         long,
         default_value = &config::DEFAULT_CONFIG,
         help = "Path to the config file"
     )]
    pub config: PathBuf,

    #[structopt(short, long, help = "Shows more information")]
    pub verbose: bool,

    #[structopt(subcommand)]
    pub cmd: Command,
}

#[derive(StructOpt)]
pub enum Command {
    #[structopt(about = "Prints functions in order of calls")]
    Calls {
        #[structopt(parse(from_os_str), help = "Path to the input trace file")]
        trace: PathBuf,

        #[structopt(
            parse(from_os_str),
            short,
            long,
            help = "Optional path to the input dump file (enables resolving names of functions)"
        )]
        dump: Option<PathBuf>,

        #[structopt(short, long, default_value = "2", help = "Indentation size")]
        tab: usize,
    },

    #[structopt(about = "Generates performance profile")]
    Generate {
        #[structopt(parse(from_os_str), help = "Path to the input trace file")]
        trace: PathBuf,

        #[structopt(
            parse(from_os_str),
            short,
            long,
            help = "Optional path to the generated assembly file (enables line-by-line profiling)"
        )]
        asm: Option<PathBuf>,

        #[structopt(
            parse(from_os_str),
            short,
            long,
            help = "Optional path to the input dump file (enables resolving names of functions)"
        )]
        dump: Option<PathBuf>,

        #[structopt(
            short,
            long,
            possible_values(&config::FORMATS),
            default_value = &config::DEFAULT_FORMAT,
            help = "Format of the generated profile"
        )]
        format: String,

        #[structopt(
            parse(from_os_str),
            short,
            long,
            help = "Path to the generated profile [default: standard output]"
        )]
        output: Option<PathBuf>,
    },
}

/// Constructs an instance of the Application.
pub fn application() -> Application {
    Application::from_args()
}
