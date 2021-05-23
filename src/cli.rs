//! bpf-profile options parser.

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

    #[structopt(subcommand)]
    pub cmd: Command,
}

#[derive(StructOpt)]
pub enum Command {
    #[structopt(about = "Generates performance profile from BPF trace")]
    Generate {
        #[structopt(parse(from_os_str), help = "Path to the input trace file")]
        trace: PathBuf,

        #[structopt(
            parse(from_os_str),
            short,
            long,
            default_value = &config::DEFAULT_ASM,
            help = "Path to the generated assembly file"
        )]
        asm: PathBuf,

        #[structopt(
            parse(from_os_str),
            short,
            long,
            help = "Optional path to the input dump file"
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
            help = "Path to the generated profile [default: stdout]"
        )]
        output: Option<PathBuf>,
    },
}

/// Constructs an instance of the Application.
pub fn application() -> Application {
    Application::from_args()
}
