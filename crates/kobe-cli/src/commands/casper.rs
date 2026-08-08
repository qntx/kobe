//! Casper Network wallet CLI commands.

use clap::{Args, Subcommand, ValueEnum};
use kobe::casper::{CasperAccount, Deriver, KeyAlgo};
use kobe::{DerivationStyle as _, DeriveExt, Wallet};

use crate::commands::simple::SimpleArgs;
use crate::output::{self, AccountOutput, HdWalletOutput};

/// Casper wallet operations.
#[derive(Args, Debug)]
pub(crate) struct CasperCommand {
    #[command(subcommand)]
    command: CasperSubcommand,
}

#[derive(Subcommand, Debug)]
enum CasperSubcommand {
    /// Generate a new wallet (with mnemonic).
    New {
        #[command(flatten)]
        args: CasperArgs,
    },
    /// Import wallet from mnemonic phrase.
    Import {
        /// BIP-39 mnemonic (`-` = read one line from stdin; avoids shell history).
        #[arg(short, long)]
        mnemonic: String,

        #[command(flatten)]
        args: CasperArgs,
    },
}

/// CLI-facing mirror of [`kobe::casper::KeyAlgo`].
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
enum CliKeyAlgo {
    /// secp256k1 — Ledger path `m/44'/506'/0'/0/{i}` (default).
    #[default]
    #[value(alias = "secp", alias = "ecdsa")]
    Secp256k1,
    /// Ed25519 — SLIP-10 path `m/44'/506'/0'/0'/{i}'`.
    #[value(alias = "ed", alias = "eddsa")]
    Ed25519,
}

impl From<CliKeyAlgo> for KeyAlgo {
    fn from(value: CliKeyAlgo) -> Self {
        match value {
            CliKeyAlgo::Secp256k1 => Self::Secp256k1,
            CliKeyAlgo::Ed25519 => Self::Ed25519,
        }
    }
}

/// Casper-specific CLI flags layered on shared mnemonic / count options.
#[derive(Args, Debug, Clone)]
struct CasperArgs {
    /// Signature algorithm / derivation path layout.
    #[arg(long, value_enum, default_value_t = CliKeyAlgo::Secp256k1)]
    algo: CliKeyAlgo,

    #[command(flatten)]
    common: SimpleArgs,
}

impl CasperCommand {
    pub(crate) fn execute(
        self,
        json: bool,
        reveal: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mnemonic, args) = match self.command {
            CasperSubcommand::New { args } => (None, args),
            CasperSubcommand::Import { mnemonic, args } => (Some(mnemonic), args),
        };
        let wallet = args.common.build_wallet(mnemonic.as_deref())?;

        let algo = KeyAlgo::from(args.algo);
        let deriver = Deriver::with_algo(&wallet, algo);
        let accounts = deriver.derive_many(0, args.common.count)?;
        let out = build_hd(&wallet, algo, &accounts, reveal);
        output::render_hd_wallet(&out, json, args.common.qr)?;
        Ok(())
    }
}

fn build_hd(
    wallet: &Wallet,
    algo: KeyAlgo,
    accounts: &[CasperAccount],
    reveal: bool,
) -> HdWalletOutput {
    HdWalletOutput::new(
        "casper",
        wallet,
        None,
        None,
        Some(algo.name()),
        accounts
            .iter()
            .enumerate()
            .map(|(i, a)| AccountOutput::from_derived(i, a.as_ref(), reveal))
            .collect(),
        reveal,
    )
}
