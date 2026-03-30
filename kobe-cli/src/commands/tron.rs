//! Tron wallet CLI commands.

use clap::{Args, Subcommand};
use kobe::tron::Deriver;
use kobe::{DeriveExt, Wallet};

use crate::output::{self, AccountOutput, HdWalletOutput};

/// Tron wallet operations.
#[derive(Args)]
pub struct TronCommand {
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
    pub fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
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
                output::render_hd_wallet(&build("tron", &wallet, &accounts), json, qr)?;
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
                output::render_hd_wallet(&build("tron", &wallet, &accounts), json, qr)?;
            }
        }
        Ok(())
    }
}

fn build(
    chain: &'static str,
    wallet: &Wallet,
    accounts: &[kobe::DerivedAccount],
) -> HdWalletOutput {
    HdWalletOutput {
        chain,
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
