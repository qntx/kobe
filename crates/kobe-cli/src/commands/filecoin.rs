//! Filecoin wallet CLI commands.

use clap::{Args, Subcommand};
use kobe::fil::Deriver;
use kobe::{DeriveExt, Wallet};

use crate::output::{self, HdWalletOutput};

/// Filecoin wallet operations.
#[derive(Args)]
pub(crate) struct FilecoinCommand {
    #[command(subcommand)]
    command: FilecoinSubcommand,
}

#[derive(Subcommand)]
enum FilecoinSubcommand {
    /// Generate a new Filecoin wallet (with mnemonic).
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

impl FilecoinCommand {
    pub(crate) fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            FilecoinSubcommand::New {
                words,
                passphrase,
                count,
                qr,
            } => {
                let wallet = Wallet::generate(words, passphrase.as_deref())?;
                let accounts = Deriver::new(&wallet).derive_many(0, count)?;
                output::render_hd_wallet(
                    &HdWalletOutput::simple("filecoin", &wallet, &accounts),
                    json,
                    qr,
                )?;
            }
            FilecoinSubcommand::Import {
                mnemonic,
                passphrase,
                count,
                qr,
            } => {
                let expanded = kobe::mnemonic::expand(&mnemonic)?;
                let wallet = Wallet::from_mnemonic(&expanded, passphrase.as_deref())?;
                let accounts = Deriver::new(&wallet).derive_many(0, count)?;
                output::render_hd_wallet(
                    &HdWalletOutput::simple("filecoin", &wallet, &accounts),
                    json,
                    qr,
                )?;
            }
        }
        Ok(())
    }
}
