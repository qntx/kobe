//! TON wallet CLI commands.

use clap::{Args, Subcommand, ValueEnum};
use kobe::ton::{AddressFormat, DerivationStyle, Deriver};
use kobe::{DerivedAccount, Wallet};

use crate::commands::simple::SimpleArgs;
use crate::output::{self, AccountOutput, HdWalletOutput};

/// TON wallet operations.
#[derive(Args, Debug)]
pub(crate) struct TonCommand {
    #[command(subcommand)]
    command: TonSubcommand,
}

#[derive(Subcommand, Debug)]
enum TonSubcommand {
    /// Generate a new wallet (with mnemonic).
    New {
        #[command(flatten)]
        args: TonArgs,
    },
    /// Import wallet from mnemonic phrase.
    Import {
        /// BIP-39 mnemonic phrase (supports 4-letter prefix expansion).
        #[arg(short, long)]
        mnemonic: String,

        #[command(flatten)]
        args: TonArgs,
    },
}

/// CLI-facing mirror of [`kobe::ton::DerivationStyle`], kept stable across
/// library refactors so `--style` values stay backward-compatible.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
enum CliDerivationStyle {
    /// `m/44'/607'/{i}'` — Tonkeeper, `MyTonWallet`, Trust Wallet.
    #[default]
    #[value(alias = "tonkeeper")]
    Standard,
    /// `m/44'/607'/{i}'/0'/0'` — Ledger Live.
    #[value(name = "ledger-live", alias = "live")]
    LedgerLive,
}

impl From<CliDerivationStyle> for DerivationStyle {
    fn from(value: CliDerivationStyle) -> Self {
        match value {
            CliDerivationStyle::Standard => Self::Standard,
            CliDerivationStyle::LedgerLive => Self::LedgerLive,
        }
    }
}

/// TON-specific CLI flags, layered on top of the shared mnemonic / count options.
///
/// The three address-format axes (network, bounceability, workchain) are
/// intentionally independent flags rather than a combined preset, matching
/// TON's own mental model: workchain selects the shard, `--testnet` flips
/// the network tag byte, `--bounceable` picks between `EQ…`/`UQ…` (mainnet)
/// or `kQ…`/`0Q…` (testnet). Key material is unaffected by these flags.
#[derive(Args, Debug, Clone)]
struct TonArgs {
    /// Use testnet instead of mainnet (flips the address tag bit and walletId).
    #[arg(short, long)]
    testnet: bool,

    /// Emit bounceable addresses (`EQ…`/`kQ…`). Default is non-bounceable (`UQ…`/`0Q…`),
    /// matching Tonkeeper's default for plain wallets.
    #[arg(short, long)]
    bounceable: bool,

    /// Workchain ID (`0` = basechain, `-1` = masterchain).
    #[arg(long, default_value_t = 0, allow_hyphen_values = true)]
    workchain: i8,

    /// Derivation path style (standard / ledger-live).
    #[arg(short, long, value_enum, default_value_t = CliDerivationStyle::Standard)]
    style: CliDerivationStyle,

    #[command(flatten)]
    common: SimpleArgs,
}

impl TonArgs {
    #[inline]
    const fn address_format(&self) -> AddressFormat {
        AddressFormat::new(self.workchain, self.bounceable, self.testnet)
    }
}

impl TonCommand {
    pub(crate) fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        let (mnemonic, args) = match self.command {
            TonSubcommand::New { args } => (None, args),
            TonSubcommand::Import { mnemonic, args } => (Some(mnemonic), args),
        };
        let wallet = args.common.build_wallet(mnemonic.as_deref())?;

        let format = args.address_format();
        let style = DerivationStyle::from(args.style);
        let deriver = Deriver::with_format(&wallet, format);
        let accounts = deriver.derive_many_with(style, 0, args.common.count)?;
        let out = build_hd(&wallet, format, style, &accounts);
        output::render_hd_wallet(&out, json, args.common.qr)?;
        Ok(())
    }
}

fn build_hd(
    wallet: &Wallet,
    format: AddressFormat,
    style: DerivationStyle,
    accounts: &[DerivedAccount],
) -> HdWalletOutput {
    HdWalletOutput {
        chain: "ton",
        network: Some(if format.testnet { "testnet" } else { "mainnet" }),
        address_type: Some(if format.bounceable {
            "bounceable"
        } else {
            "non-bounceable"
        }),
        mnemonic: wallet.mnemonic().to_owned(),
        passphrase_protected: wallet.has_passphrase(),
        derivation_style: Some(style.name()),
        accounts: accounts
            .iter()
            .enumerate()
            .map(|(i, a)| AccountOutput::from_derived(i, a))
            .collect(),
    }
}
