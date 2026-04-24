//! Solana wallet CLI commands.

use clap::{Args, Subcommand, ValueEnum};
use kobe::svm::{DerivationStyle, Deriver, SvmAccount};
use kobe::{DerivationStyle as _, Wallet};

use crate::commands::simple::SimpleArgs;
use crate::output::{self, AccountOutput, HdWalletOutput};

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
enum CliDerivationStyle {
    #[default]
    #[value(alias = "phantom", alias = "backpack")]
    Standard,
    #[value(alias = "ledger", alias = "keystone")]
    Trust,
    LedgerLive,
    #[value(alias = "old")]
    Legacy,
}

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
pub(crate) struct SolanaCommand {
    #[command(subcommand)]
    command: SolanaSubcommand,
}

#[derive(Subcommand)]
enum SolanaSubcommand {
    /// Generate a new wallet (with mnemonic).
    New {
        #[command(flatten)]
        args: SolanaArgs,
    },
    /// Import wallet from mnemonic phrase.
    Import {
        /// BIP39 mnemonic phrase.
        #[arg(short, long)]
        mnemonic: String,

        #[command(flatten)]
        args: SolanaArgs,
    },
}

/// Solana-specific CLI flags, on top of the shared mnemonic / count options.
#[derive(Args, Debug, Clone)]
struct SolanaArgs {
    /// Derivation path style (standard, trust, ledger-live, legacy).
    #[arg(short, long, default_value = "standard")]
    style: CliDerivationStyle,

    #[command(flatten)]
    common: SimpleArgs,
}

impl SolanaCommand {
    pub(crate) fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        let (mnemonic, args) = match self.command {
            SolanaSubcommand::New { args } => (None, args),
            SolanaSubcommand::Import { mnemonic, args } => (Some(mnemonic), args),
        };
        let wallet = args.common.build_wallet(mnemonic.as_deref())?;

        let ds = DerivationStyle::from(args.style);
        let deriver = Deriver::new(&wallet);
        let addresses = deriver.derive_many_with(ds, 0, args.common.count)?;
        let out = build_hd(&wallet, ds, &addresses);
        output::render_hd_wallet(&out, json, args.common.qr)?;
        Ok(())
    }
}

fn build_hd(wallet: &Wallet, style: DerivationStyle, addresses: &[SvmAccount]) -> HdWalletOutput {
    HdWalletOutput {
        chain: "solana",
        network: None,
        address_type: None,
        mnemonic: wallet.mnemonic().to_owned(),
        passphrase_protected: wallet.has_passphrase(),
        derivation_style: Some(style.name()),
        accounts: addresses
            .iter()
            .enumerate()
            .map(|(i, a)| AccountOutput {
                index: u32::try_from(i).unwrap_or(u32::MAX),
                derivation_path: a.path().to_owned(),
                address: a.address().to_owned(),
                private_key: a.keypair_base58().as_str().to_owned(),
            })
            .collect(),
    }
}
