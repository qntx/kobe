//! Kobe - A multi-chain cryptocurrency wallet CLI tool.
//!
//! Easily generate and manage wallets for Bitcoin and Ethereum.

mod commands;

use clap::Parser;
use commands::{Cli, Commands};

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Commands::Bitcoin(cmd) => cmd.execute()?,
        Commands::Ethereum(cmd) => cmd.execute()?,
    }
    Ok(())
}
