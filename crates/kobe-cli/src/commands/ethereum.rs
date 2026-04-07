//! Ethereum wallet CLI commands.

use clap::{Args, Subcommand, ValueEnum};
use kobe::Wallet;
use kobe::evm::{DerivationStyle, Deriver};

use crate::output::{self, AccountOutput, HdWalletOutput};

/// Ethereum wallet operations.
#[derive(Args)]
pub(crate) struct EthereumCommand {
    #[command(subcommand)]
    command: EthereumSubcommand,
}

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum CliDerivationStyle {
    #[default]
    Standard,
    #[value(name = "ledger-live")]
    LedgerLive,
    #[value(name = "ledger-legacy")]
    LedgerLegacy,
}

impl From<CliDerivationStyle> for DerivationStyle {
    fn from(style: CliDerivationStyle) -> Self {
        match style {
            CliDerivationStyle::Standard => Self::Standard,
            CliDerivationStyle::LedgerLive => Self::LedgerLive,
            CliDerivationStyle::LedgerLegacy => Self::LedgerLegacy,
        }
    }
}

#[derive(Subcommand)]
enum EthereumSubcommand {
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

impl EthereumCommand {
    pub(crate) fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            EthereumSubcommand::New {
                words,
                passphrase,
                count,
                style,
                qr,
            } => {
                let ds = DerivationStyle::from(style);
                let wallet = Wallet::generate(words, passphrase.as_deref())?;
                let deriver = Deriver::new(&wallet);
                let accounts = deriver.derive_many_with(ds, 0, count)?;
                let out = build_hd(&wallet, ds, &accounts);
                output::render_hd_wallet(&out, json, qr)?;
            }
            EthereumSubcommand::Import {
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
                let accounts = deriver.derive_many_with(ds, 0, count)?;
                let out = build_hd(&wallet, ds, &accounts);
                output::render_hd_wallet(&out, json, qr)?;
            }
        }
        Ok(())
    }
}

fn build_hd(
    wallet: &Wallet,
    style: DerivationStyle,
    accounts: &[kobe::DerivedAccount],
) -> HdWalletOutput {
    HdWalletOutput {
        chain: "ethereum",
        network: None,
        address_type: None,
        mnemonic: wallet.mnemonic().to_owned(),
        passphrase_protected: wallet.has_passphrase(),
        derivation_style: Some(style.name()),
        accounts: accounts
            .iter()
            .enumerate()
            .map(|(i, a)| AccountOutput {
                index: u32::try_from(i).unwrap_or(u32::MAX),
                derivation_path: a.path.clone(),
                address: a.address.clone(),
                private_key: format!("0x{}", a.private_key.as_str()),
            })
            .collect(),
    }
}
