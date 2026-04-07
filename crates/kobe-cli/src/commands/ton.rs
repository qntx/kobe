//! TON wallet CLI commands.

use clap::{Args, Subcommand};
use kobe::ton::Deriver;
use kobe::{DeriveExt, Wallet};

use crate::output::{self, HdWalletOutput};

/// TON wallet operations.
#[derive(Args)]
pub(crate) struct TonCommand {
    #[command(subcommand)]
    command: TonSubcommand,
}

#[derive(Subcommand)]
enum TonSubcommand {
    /// Generate a new TON wallet (with mnemonic).
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

impl TonCommand {
    pub(crate) fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            TonSubcommand::New {
                words,
                passphrase,
                count,
                qr,
            } => {
                let wallet = Wallet::generate(words, passphrase.as_deref())?;
                let accounts = Deriver::new(&wallet).derive_many(0, count)?;
                output::render_hd_wallet(
                    &HdWalletOutput::simple("ton", &wallet, &accounts),
                    json,
                    qr,
                )?;
            }
            TonSubcommand::Import {
                mnemonic,
                passphrase,
                count,
                qr,
            } => {
                let expanded = kobe::mnemonic::expand(&mnemonic)?;
                let wallet = Wallet::from_mnemonic(&expanded, passphrase.as_deref())?;
                let accounts = Deriver::new(&wallet).derive_many(0, count)?;
                output::render_hd_wallet(
                    &HdWalletOutput::simple("ton", &wallet, &accounts),
                    json,
                    qr,
                )?;
            }
        }
        Ok(())
    }
}
