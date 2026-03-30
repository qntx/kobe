//! Sui wallet CLI commands.

use clap::{Args, Subcommand};
use kobe::sui::Deriver;
use kobe::{DeriveExt, Wallet};

use crate::output::{self, AccountOutput, HdWalletOutput};

/// Sui wallet operations.
#[derive(Args)]
pub struct SuiCommand {
    #[command(subcommand)]
    command: SuiSubcommand,
}

#[derive(Subcommand)]
enum SuiSubcommand {
    /// Generate a new Sui wallet (with mnemonic).
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

impl SuiCommand {
    pub fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            SuiSubcommand::New {
                words,
                passphrase,
                count,
                qr,
            } => {
                let wallet = Wallet::generate(words, passphrase.as_deref())?;
                let accounts = Deriver::new(&wallet).derive_many(0, count)?;
                output::render_hd_wallet(&build(&wallet, &accounts), json, qr)?;
            }
            SuiSubcommand::Import {
                mnemonic,
                passphrase,
                count,
                qr,
            } => {
                let expanded = kobe::mnemonic::expand(&mnemonic)?;
                let wallet = Wallet::from_mnemonic(&expanded, passphrase.as_deref())?;
                let accounts = Deriver::new(&wallet).derive_many(0, count)?;
                output::render_hd_wallet(&build(&wallet, &accounts), json, qr)?;
            }
        }
        Ok(())
    }
}

fn build(wallet: &Wallet, accounts: &[kobe::DerivedAccount]) -> HdWalletOutput {
    HdWalletOutput {
        chain: "sui",
        network: None,
        address_type: None,
        mnemonic: wallet.mnemonic().to_string(),
        passphrase_protected: wallet.has_passphrase(),
        derivation_style: None,
        accounts: accounts
            .iter()
            .enumerate()
            .map(|(i, a)| AccountOutput {
                index: u32::try_from(i).unwrap_or(u32::MAX),
                derivation_path: a.path.clone(),
                address: a.address.clone(),
                private_key: a.private_key.to_string(),
            })
            .collect(),
    }
}
