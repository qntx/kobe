#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    missing_docs,
    reason = "CLI binary legitimately prints to stdout/stderr and does not require public docs"
)]
//! Kobe — multi-chain cryptocurrency wallet CLI.

mod commands;
pub mod output;
pub mod qr;

use clap::Parser;
use commands::{Cli, Commands};

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let json = cli.json;

    if let Err(e) = run(cli) {
        if json {
            let err = output::ErrorOutput {
                error: e.to_string(),
            };
            output::print_json(&err).ok();
        } else {
            eprintln!("Error: {e}");
        }
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

/// Dispatch CLI commands and propagate errors.
fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let json = cli.json;
    let reveal = cli.reveal;
    match cli.command {
        Commands::Aptos(cmd) => cmd.execute(json, reveal)?,
        Commands::Bitcoin(cmd) => cmd.execute(json, reveal)?,
        Commands::Ethereum(cmd) => cmd.execute(json, reveal)?,
        Commands::Solana(cmd) => cmd.execute(json, reveal)?,
        Commands::Cosmos(cmd) => cmd.execute(json, reveal)?,
        Commands::Tron(cmd) => cmd.execute(json, reveal)?,
        Commands::Spark(cmd) => cmd.execute(json, reveal)?,
        Commands::Filecoin(cmd) => cmd.execute(json, reveal)?,
        Commands::Ton(cmd) => cmd.execute(json, reveal)?,
        Commands::Sui(cmd) => cmd.execute(json, reveal)?,
        Commands::Xrpl(cmd) => cmd.execute(json, reveal)?,
        Commands::Nostr(cmd) => cmd.execute(json, reveal)?,
        Commands::Mnemonic(cmd) => cmd.execute(json)?,
    }
    Ok(())
}
