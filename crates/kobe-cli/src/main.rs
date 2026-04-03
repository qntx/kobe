#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::missing_docs_in_private_items,
    missing_docs
)]
//! Kobe — multi-chain cryptocurrency wallet CLI.

mod commands;
pub mod output;
pub mod qr;

use clap::Parser;
use commands::{Cli, Commands};

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

/// Dispatch CLI commands and propagate errors.
fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let json = cli.json;
    match cli.command {
        Commands::Bitcoin(cmd) => cmd.execute(json)?,
        Commands::Ethereum(cmd) => cmd.execute(json)?,
        Commands::Solana(cmd) => cmd.execute(json)?,
        Commands::Cosmos(cmd) => cmd.execute(json)?,
        Commands::Tron(cmd) => cmd.execute(json)?,
        Commands::Spark(cmd) => cmd.execute(json)?,
        Commands::Filecoin(cmd) => cmd.execute(json)?,
        Commands::Ton(cmd) => cmd.execute(json)?,
        Commands::Sui(cmd) => cmd.execute(json)?,
        Commands::Xrpl(cmd) => cmd.execute(json)?,
        Commands::Mnemonic(cmd) => cmd.execute(json)?,
    }
    Ok(())
}
