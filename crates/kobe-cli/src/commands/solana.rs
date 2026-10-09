//! Solana wallet CLI commands.

use clap::{Args, Subcommand, ValueEnum};
use kobe::svm::{DerivationStyle, Deriver, SvmAccount};
use kobe::{DerivationStyle as _, Wallet};

use crate::commands::simple::SimpleArgs;
use crate::output::{self, AccountOutput, HdWalletOutput};

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
enum CliDerivationStyle {
    /// `m/44'/501'/{index}'/0'` — Phantom, Solflare, Backpack, `MetaMask`, OKX, solana-keygen.
    #[default]
    #[value(
        name = "bip44-change",
        alias = "phantom",
        alias = "solflare",
        alias = "backpack"
    )]
    Bip44Change,
    /// `m/44'/501'/{index}'` — Trust Wallet, Ledger Live, Keystone.
    #[value(
        name = "bip44",
        alias = "trust",
        alias = "ledger",
        alias = "ledger-live",
        alias = "keystone"
    )]
    Bip44,
    /// `m/501'/{index}'/0'/0'` — Sollet (deprecated, import only).
    #[value(alias = "sollet", alias = "old")]
    Legacy,
}

impl From<CliDerivationStyle> for DerivationStyle {
    fn from(style: CliDerivationStyle) -> Self {
        match style {
            CliDerivationStyle::Bip44Change => Self::Bip44Change,
            CliDerivationStyle::Bip44 => Self::Bip44,
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
    /// Derivation path style (bip44-change, bip44, legacy).
    #[arg(short, long, default_value = "bip44-change")]
    style: CliDerivationStyle,

    #[command(flatten)]
    common: SimpleArgs,
}

impl SolanaCommand {
    pub(crate) fn execute(
        self,
        json: bool,
        reveal: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mnemonic, args) = match self.command {
            SolanaSubcommand::New { args } => (None, args),
            SolanaSubcommand::Import { mnemonic, args } => (Some(mnemonic), args),
        };
        let wallet = args.common.build_wallet(mnemonic.as_deref())?;

        let ds = DerivationStyle::from(args.style);
        let deriver = Deriver::new(&wallet);
        let addresses = deriver.derive_many_with(ds, 0, args.common.count)?;
        let out = build_hd(&wallet, ds, &addresses, reveal);
        output::render_hd_wallet(&out, json, args.common.qr)?;
        Ok(())
    }
}

fn build_hd(
    wallet: &Wallet,
    style: DerivationStyle,
    addresses: &[SvmAccount],
    reveal: bool,
) -> HdWalletOutput {
    HdWalletOutput::new(
        "solana",
        wallet,
        None,
        None,
        Some(style.name()),
        addresses
            .iter()
            .enumerate()
            .map(|(i, a)| {
                AccountOutput::from_parts(
                    i,
                    a.path(),
                    a.address(),
                    a.keypair_base58().as_str(),
                    reveal,
                )
            })
            .collect(),
        reveal,
    )
}
