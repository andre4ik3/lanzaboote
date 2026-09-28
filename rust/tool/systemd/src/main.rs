mod architecture;
mod cli;
mod esp;
mod guard;
mod install;
mod pcrlock;
mod tpm;
mod version;

use clap::Parser;

use cli::Cli;

fn main() {
    Cli::parse().call(module_path!())
}
