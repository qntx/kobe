//! CLI command definitions and handlers.

mod bitcoin;
mod cosmos;
mod ethereum;
mod filecoin;
mod mnemonic;
mod solana;
mod spark;
mod sui;
mod ton;
mod tron;
mod xrpl;

pub use bitcoin::BitcoinCommand;
use clap::{Parser, Subcommand};
pub use cosmos::CosmosCommand;
pub use ethereum::EthereumCommand;
pub use filecoin::FilecoinCommand;
pub use mnemonic::MnemonicCommand;
pub use solana::SolanaCommand;
pub use spark::SparkCommand;
pub use sui::SuiCommand;
pub use ton::TonCommand;
pub use tron::TronCommand;
pub use xrpl::XrplCommand;

/// Kobe - A multi-chain cryptocurrency wallet CLI tool.
#[derive(Parser)]
#[command(name = "kobe")]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    /// Output results in JSON format for programmatic/agent consumption.
    #[arg(long, global = true)]
    pub json: bool,

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
    #[command(name = "evm", alias = "eth", alias = "ethereum")]
    Ethereum(EthereumCommand),

    /// Solana wallet operations.
    #[command(name = "svm", alias = "sol", alias = "solana")]
    Solana(SolanaCommand),

    /// Cosmos wallet operations.
    #[command(name = "cosmos", alias = "atom")]
    Cosmos(CosmosCommand),

    /// Tron wallet operations.
    #[command(name = "tron", alias = "trx")]
    Tron(TronCommand),

    /// Spark (Bitcoin L2) wallet operations.
    #[command(name = "spark")]
    Spark(SparkCommand),

    /// Filecoin wallet operations.
    #[command(name = "fil", alias = "filecoin")]
    Filecoin(FilecoinCommand),

    /// TON wallet operations.
    #[command(name = "ton")]
    Ton(TonCommand),

    /// Sui wallet operations.
    #[command(name = "sui")]
    Sui(SuiCommand),

    /// XRP Ledger wallet operations.
    #[command(name = "xrpl", alias = "xrp", alias = "ripple")]
    Xrpl(XrplCommand),

    /// Mnemonic utilities (camouflage encrypt/decrypt).
    #[command(name = "mnemonic", alias = "mn")]
    Mnemonic(MnemonicCommand),
}
