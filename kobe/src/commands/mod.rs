//! CLI command definitions and handlers.

mod bitcoin;
mod ethereum;

pub use bitcoin::BitcoinCommand;
pub use ethereum::EthereumCommand;

use clap::{Parser, Subcommand};

/// Kobe - A multi-chain cryptocurrency wallet CLI tool.
#[derive(Parser)]
#[command(name = "kobe")]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

/// Available blockchain commands.
#[derive(Subcommand)]
pub enum Commands {
    /// Bitcoin wallet operations.
    #[command(name = "btc", alias = "bitcoin")]
    Bitcoin(BitcoinCommand),

    /// Ethereum wallet operations.
    #[command(name = "eth", alias = "ethereum")]
    Ethereum(EthereumCommand),
}
