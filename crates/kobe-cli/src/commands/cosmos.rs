//! Cosmos wallet CLI commands.

use clap::{Args, Subcommand};
use kobe::cosmos::Deriver;
use kobe::{DeriveExt, Wallet};

use crate::output::{self, AccountOutput, HdWalletOutput};

/// Cosmos wallet operations.
#[derive(Args)]
pub struct CosmosCommand {
    #[command(subcommand)]
    command: CosmosSubcommand,
}

#[derive(Subcommand)]
enum CosmosSubcommand {
    /// Generate a new Cosmos wallet (with mnemonic).
    New {
        #[arg(short, long, default_value = "12")]
        words: usize,
        #[arg(short, long)]
        passphrase: Option<String>,
        #[arg(short, long, default_value = "1")]
        count: u32,
        #[arg(long, default_value = "cosmos")]
        hrp: String,
        #[arg(long, default_value = "118")]
        coin_type: u32,
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
        #[arg(long, default_value = "cosmos")]
        hrp: String,
        #[arg(long, default_value = "118")]
        coin_type: u32,
        #[arg(long)]
        qr: bool,
    },
}

impl CosmosCommand {
    pub fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            CosmosSubcommand::New {
                words,
                passphrase,
                count,
                hrp,
                coin_type,
                qr,
            } => {
                let wallet = Wallet::generate(words, passphrase.as_deref())?;
                let deriver = Deriver::with_config(&wallet, &hrp, coin_type);
                let accounts = deriver.derive_many(0, count)?;
                let out = build_hd(&wallet, &accounts);
                output::render_hd_wallet(&out, json, qr)?;
            }
            CosmosSubcommand::Import {
                mnemonic,
                passphrase,
                count,
                hrp,
                coin_type,
                qr,
            } => {
                let expanded = kobe::mnemonic::expand(&mnemonic)?;
                let wallet = Wallet::from_mnemonic(&expanded, passphrase.as_deref())?;
                let deriver = Deriver::with_config(&wallet, &hrp, coin_type);
                let accounts = deriver.derive_many(0, count)?;
                let out = build_hd(&wallet, &accounts);
                output::render_hd_wallet(&out, json, qr)?;
            }
        }
        Ok(())
    }
}

fn build_hd(wallet: &Wallet, accounts: &[kobe::DerivedAccount]) -> HdWalletOutput {
    HdWalletOutput {
        chain: "cosmos",
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
