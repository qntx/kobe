//! CLI command definitions and handlers.

mod aptos;
mod bitcoin;
mod cosmos;
mod ethereum;
mod filecoin;
mod mnemonic;
mod nostr;
mod simple;
mod solana;
mod spark;
mod sui;
mod ton;
mod tron;
mod xrpl;

pub(crate) use aptos::AptosCommand;
pub(crate) use bitcoin::BitcoinCommand;
use clap::{Parser, Subcommand};
pub(crate) use cosmos::CosmosCommand;
pub(crate) use ethereum::EthereumCommand;
pub(crate) use filecoin::FilecoinCommand;
pub(crate) use mnemonic::MnemonicCommand;
pub(crate) use nostr::NostrCommand;
pub(crate) use simple::SimpleSubcommand;
pub(crate) use solana::SolanaCommand;
pub(crate) use spark::SparkCommand;
pub(crate) use sui::SuiCommand;
pub(crate) use ton::TonCommand;
pub(crate) use tron::TronCommand;
pub(crate) use xrpl::XrplCommand;

/// Kobe - A multi-chain cryptocurrency wallet CLI tool.
#[derive(Parser)]
#[command(name = "kobe")]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
pub(crate) struct Cli {
    /// Output results in JSON format for programmatic/agent consumption.
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Commands,
}

/// Available blockchain commands.
#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Aptos wallet operations.
    #[command(name = "aptos", alias = "apt")]
    Aptos(AptosCommand),

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

    /// Nostr wallet operations (NIP-06 / NIP-19).
    #[command(name = "nostr")]
    Nostr(NostrCommand),

    /// Mnemonic utilities (camouflage encrypt/decrypt).
    #[command(name = "mnemonic", alias = "mn")]
    Mnemonic(MnemonicCommand),
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::Cli;

    /// `clap`'s built-in self-consistency check. Catches conflicting short
    /// flags, duplicate subcommand names, malformed `value_enum` derives,
    /// and other structural mistakes at `cargo test` time instead of at
    /// first CLI invocation. Recommended for every production `clap` app.
    #[test]
    fn cli_structure_is_consistent() {
        Cli::command().debug_assert();
    }
}
