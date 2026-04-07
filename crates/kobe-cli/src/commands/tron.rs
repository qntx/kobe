//! Tron wallet CLI commands.

use clap::{Args, Subcommand};
use kobe::tron::Deriver;
use kobe::{DeriveExt, Wallet};

use crate::output::{self, HdWalletOutput};

/// Tron wallet operations.
#[derive(Args)]
pub(crate) struct TronCommand {
    #[command(subcommand)]
    command: TronSubcommand,
}

#[derive(Subcommand)]
enum TronSubcommand {
    /// Generate a new Tron wallet (with mnemonic).
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

impl TronCommand {
    pub(crate) fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            TronSubcommand::New {
                words,
                passphrase,
                count,
                qr,
            } => {
                let wallet = Wallet::generate(words, passphrase.as_deref())?;
                let deriver = Deriver::new(&wallet);
                let accounts = deriver.derive_many(0, count)?;
                output::render_hd_wallet(
                    &HdWalletOutput::simple("tron", &wallet, &accounts),
                    json,
                    qr,
                )?;
            }
            TronSubcommand::Import {
                mnemonic,
                passphrase,
                count,
                qr,
            } => {
                let expanded = kobe::mnemonic::expand(&mnemonic)?;
                let wallet = Wallet::from_mnemonic(&expanded, passphrase.as_deref())?;
                let deriver = Deriver::new(&wallet);
                let accounts = deriver.derive_many(0, count)?;
                output::render_hd_wallet(
                    &HdWalletOutput::simple("tron", &wallet, &accounts),
                    json,
                    qr,
                )?;
            }
        }
        Ok(())
    }
}
