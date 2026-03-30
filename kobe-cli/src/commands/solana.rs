//! Solana wallet CLI commands.

use clap::{Args, Subcommand, ValueEnum};
use kobe::Wallet;
use kobe_svm::{DerivationStyle, Deriver};

use crate::output::{self, AccountOutput, HdWalletOutput};

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum CliDerivationStyle {
    #[default]
    #[value(alias = "phantom", alias = "backpack")]
    Standard,
    #[value(alias = "ledger", alias = "keystone")]
    Trust,
    LedgerLive,
    #[value(alias = "old")]
    Legacy,
}

#[allow(deprecated)]
impl From<CliDerivationStyle> for DerivationStyle {
    fn from(style: CliDerivationStyle) -> Self {
        match style {
            CliDerivationStyle::Standard => Self::Standard,
            CliDerivationStyle::Trust => Self::Trust,
            CliDerivationStyle::LedgerLive => Self::LedgerLive,
            CliDerivationStyle::Legacy => Self::Legacy,
        }
    }
}

/// Solana wallet operations.
#[derive(Args)]
pub struct SolanaCommand {
    #[command(subcommand)]
    command: SolanaSubcommand,
}

#[derive(Subcommand)]
enum SolanaSubcommand {
    /// Generate a new wallet (with mnemonic).
    New {
        #[arg(short, long, default_value = "12")]
        words: usize,
        #[arg(short, long)]
        passphrase: Option<String>,
        #[arg(short, long, default_value = "1")]
        count: u32,
        #[arg(short, long, default_value = "standard")]
        style: CliDerivationStyle,
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
        #[arg(short, long, default_value = "standard")]
        style: CliDerivationStyle,
        #[arg(long)]
        qr: bool,
    },
}

impl SolanaCommand {
    pub fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            SolanaSubcommand::New {
                words,
                passphrase,
                count,
                style,
                qr,
            } => {
                let ds = DerivationStyle::from(style);
                let wallet = Wallet::generate(words, passphrase.as_deref())?;
                let deriver = Deriver::new(&wallet);
                let addresses = deriver.derive_many_with(ds, 0, count)?;
                let out = build_hd(&wallet, ds, &addresses);
                output::render_hd_wallet(&out, json, qr)?;
            }
            SolanaSubcommand::Import {
                mnemonic,
                passphrase,
                count,
                style,
                qr,
            } => {
                let ds = DerivationStyle::from(style);
                let expanded = kobe::mnemonic::expand(&mnemonic)?;
                let wallet = Wallet::from_mnemonic(&expanded, passphrase.as_deref())?;
                let deriver = Deriver::new(&wallet);
                let addresses = deriver.derive_many_with(ds, 0, count)?;
                let out = build_hd(&wallet, ds, &addresses);
                output::render_hd_wallet(&out, json, qr)?;
            }
        }
        Ok(())
    }
}

fn build_hd(
    wallet: &Wallet,
    style: DerivationStyle,
    addresses: &[kobe_svm::DerivedAddress],
) -> HdWalletOutput {
    HdWalletOutput {
        chain: "solana",
        network: None,
        address_type: None,
        mnemonic: wallet.mnemonic().to_string(),
        passphrase_protected: wallet.has_passphrase(),
        derivation_style: Some(style.name()),
        accounts: addresses
            .iter()
            .enumerate()
            .map(|(i, a)| AccountOutput {
                index: u32::try_from(i).unwrap_or(u32::MAX),
                derivation_path: a.path.clone(),
                address: a.address.clone(),
                private_key: a.keypair_base58.to_string(),
            })
            .collect(),
    }
}
