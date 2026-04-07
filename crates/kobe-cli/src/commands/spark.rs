//! Spark wallet CLI commands.

use clap::{Args, Subcommand};
use kobe::spark::Deriver;
use kobe::{DeriveExt, Wallet};

use crate::output::{self, HdWalletOutput};

/// Spark (Bitcoin L2) wallet operations.
#[derive(Args)]
pub(crate) struct SparkCommand {
    #[command(subcommand)]
    command: SparkSubcommand,
}

#[derive(Subcommand)]
enum SparkSubcommand {
    /// Generate a new Spark wallet (with mnemonic).
    New {
        #[arg(short, long, default_value = "12")]
        words: usize,
        #[arg(short, long)]
        passphrase: Option<String>,
        #[arg(short, long, default_value = "1")]
        count: u32,
        #[arg(long)]
        qr: bool,
    },
    /// Import wallet from mnemonic phrase.
    Import {
        #[arg(short, long)]
        mnemonic: String,
        #[arg(short, long)]
        passphrase: Option<String>,
        #[arg(short, long, default_value = "1")]
        count: u32,
        #[arg(long)]
        qr: bool,
    },
}

impl SparkCommand {
    pub(crate) fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            SparkSubcommand::New {
                words,
                passphrase,
                count,
                qr,
            } => {
                let wallet = Wallet::generate(words, passphrase.as_deref())?;
                let accounts = Deriver::new(&wallet).derive_many(0, count)?;
                output::render_hd_wallet(
                    &HdWalletOutput::simple("spark", &wallet, &accounts),
                    json,
                    qr,
                )?;
            }
            SparkSubcommand::Import {
                mnemonic,
                passphrase,
                count,
                qr,
            } => {
                let expanded = kobe::mnemonic::expand(&mnemonic)?;
                let wallet = Wallet::from_mnemonic(&expanded, passphrase.as_deref())?;
                let accounts = Deriver::new(&wallet).derive_many(0, count)?;
                output::render_hd_wallet(
                    &HdWalletOutput::simple("spark", &wallet, &accounts),
                    json,
                    qr,
                )?;
            }
        }
        Ok(())
    }
}
