//! Ethereum wallet CLI commands.

use clap::{Args, Subcommand, ValueEnum};
use kobe::evm::{DerivationStyle, Deriver};
use kobe::{DerivationStyle as _, DerivedAccount, Wallet};

use crate::commands::simple::SimpleArgs;
use crate::output::{self, AccountOutput, HdWalletOutput};

/// Ethereum wallet operations.
#[derive(Args)]
pub(crate) struct EthereumCommand {
    #[command(subcommand)]
    command: EthereumSubcommand,
}

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
enum CliDerivationStyle {
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
        #[command(flatten)]
        args: EthereumArgs,
    },
    /// Import wallet from mnemonic phrase.
    Import {
        /// BIP39 mnemonic phrase.
        #[arg(short, long)]
        mnemonic: String,

        #[command(flatten)]
        args: EthereumArgs,
    },
}

/// Ethereum-specific CLI flags, on top of the shared mnemonic / count options.
#[derive(Args, Debug, Clone)]
struct EthereumArgs {
    /// Derivation path style (standard / ledger-live / ledger-legacy).
    #[arg(short, long, default_value = "standard")]
    style: CliDerivationStyle,

    #[command(flatten)]
    common: SimpleArgs,
}

impl EthereumCommand {
    pub(crate) fn execute(
        self,
        json: bool,
        reveal: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mnemonic, args) = match self.command {
            EthereumSubcommand::New { args } => (None, args),
            EthereumSubcommand::Import { mnemonic, args } => (Some(mnemonic), args),
        };
        let wallet = args.common.build_wallet(mnemonic.as_deref())?;

        let ds = DerivationStyle::from(args.style);
        let deriver = Deriver::new(&wallet);
        let accounts = deriver.derive_many_with(ds, 0, args.common.count)?;
        let out = build_hd(&wallet, ds, &accounts, reveal);
        output::render_hd_wallet(&out, json, args.common.qr)?;
        Ok(())
    }
}

fn build_hd(
    wallet: &Wallet,
    style: DerivationStyle,
    accounts: &[DerivedAccount],
    reveal: bool,
) -> HdWalletOutput {
    HdWalletOutput::new(
        "ethereum",
        wallet,
        None,
        None,
        Some(style.name()),
        accounts
            .iter()
            .enumerate()
            .map(|(i, a)| {
                AccountOutput::from_parts(
                    i,
                    a.path(),
                    a.address(),
                    &format!("0x{}", a.private_key_hex().as_str()),
                    reveal,
                )
            })
            .collect(),
        reveal,
    )
}
