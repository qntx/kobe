//! Spark wallet CLI commands.

use clap::{Args, Subcommand, ValueEnum};
use kobe::spark::{Deriver, Network};
use kobe::{DeriveExt, DerivedAccount, Wallet};

use crate::commands::simple::SimpleArgs;
use crate::output::{self, AccountOutput, HdWalletOutput};

/// Spark (Bitcoin L2) wallet operations.
#[derive(Args, Debug)]
pub(crate) struct SparkCommand {
    #[command(subcommand)]
    command: SparkSubcommand,
}

#[derive(Subcommand, Debug)]
enum SparkSubcommand {
    /// Generate a new wallet (with mnemonic).
    New {
        #[command(flatten)]
        args: SparkArgs,
    },
    /// Import wallet from mnemonic phrase.
    Import {
        /// BIP-39 mnemonic phrase (supports 4-letter prefix expansion).
        #[arg(short, long)]
        mnemonic: String,

        #[command(flatten)]
        args: SparkArgs,
    },
}

/// CLI-facing mirror of [`kobe::spark::Network`].
///
/// Kept as a separate enum so `clap` derives remain inside the CLI layer;
/// the library stays free of `clap` and `ValueEnum` dependencies.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
enum CliNetwork {
    /// `spark1…` — Spark mainnet.
    #[default]
    Mainnet,
    /// `sparkt1…` — Spark testnet.
    Testnet,
    /// `sparks1…` — Spark signet.
    Signet,
    /// `sparkrt1…` — Spark regtest.
    Regtest,
    /// `sparkl1…` — Spark local development network.
    Local,
}

impl From<CliNetwork> for Network {
    fn from(value: CliNetwork) -> Self {
        match value {
            CliNetwork::Mainnet => Self::Mainnet,
            CliNetwork::Testnet => Self::Testnet,
            CliNetwork::Signet => Self::Signet,
            CliNetwork::Regtest => Self::Regtest,
            CliNetwork::Local => Self::Local,
        }
    }
}

/// Spark-specific CLI flags, layered on top of the shared mnemonic / count options.
#[derive(Args, Debug, Clone)]
struct SparkArgs {
    /// Spark network (selects the Bech32m HRP: `spark` / `sparkt` / `sparks` /
    /// `sparkrt` / `sparkl`). Key derivation is independent of this flag.
    #[arg(short, long, value_enum, default_value_t = CliNetwork::Mainnet)]
    network: CliNetwork,

    #[command(flatten)]
    common: SimpleArgs,
}

impl SparkCommand {
    pub(crate) fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        let (mnemonic, args) = match self.command {
            SparkSubcommand::New { args } => (None, args),
            SparkSubcommand::Import { mnemonic, args } => (Some(mnemonic), args),
        };
        let wallet = args.common.build_wallet(mnemonic.as_deref())?;

        let network = Network::from(args.network);
        let deriver = Deriver::with_network(&wallet, network);
        let accounts = deriver.derive_many(0, args.common.count)?;
        let out = build_hd(&wallet, network, &accounts);
        output::render_hd_wallet(&out, json, args.common.qr)?;
        Ok(())
    }
}

fn build_hd(wallet: &Wallet, network: Network, accounts: &[DerivedAccount]) -> HdWalletOutput {
    HdWalletOutput {
        chain: "spark",
        network: Some(network.name()),
        address_type: None,
        mnemonic: wallet.mnemonic().to_owned(),
        passphrase_protected: wallet.has_passphrase(),
        derivation_style: None,
        accounts: accounts
            .iter()
            .enumerate()
            .map(|(i, a)| AccountOutput::from_derived(i, a))
            .collect(),
    }
}
