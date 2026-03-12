//! Kobe - A multi-chain cryptocurrency wallet CLI tool.
//!
//! Easily generate and manage wallets for Bitcoin, Ethereum, and Solana.

mod cmd;
pub mod output;
pub mod qr;

use clap::Parser;
use cmd::{Cli, Commands};

fn main() {
    let cli = Cli::parse();
    let json = cli.json;

    if let Err(e) = run(cli) {
        if json {
            let err = output::ErrorOutput {
                error: e.to_string(),
            };
            let _ = output::print_json(&err);
        } else {
            eprintln!("Error: {e}");
        }
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let json = cli.json;
    match cli.command {
        Commands::Bitcoin(cmd) => cmd.execute(json)?,
        Commands::Ethereum(cmd) => cmd.execute(json)?,
        Commands::Solana(cmd) => cmd.execute(json)?,
        Commands::Mnemonic(cmd) => cmd.execute(json)?,
    }
    Ok(())
}
