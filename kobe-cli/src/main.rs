//! Kobe - A multi-chain cryptocurrency wallet CLI tool.
//!
//! Easily generate and manage wallets for Bitcoin, Ethereum, and Solana.

mod commands;
pub mod qr;

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
        Commands::Solana(cmd) => cmd.execute()?,
    }
    Ok(())
}
