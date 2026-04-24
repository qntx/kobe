//! Cosmos wallet CLI commands.

use clap::{Args, Subcommand};
use kobe::DeriveExt;
use kobe::cosmos::{ChainConfig, Deriver};

use crate::commands::simple::SimpleArgs;
use crate::output::{self, HdWalletOutput};

/// Cosmos wallet operations.
#[derive(Args)]
pub(crate) struct CosmosCommand {
    #[command(subcommand)]
    command: CosmosSubcommand,
}

#[derive(Subcommand)]
enum CosmosSubcommand {
    /// Generate a new Cosmos wallet (with mnemonic).
    New {
        #[command(flatten)]
        args: CosmosArgs,
    },
    /// Import wallet from mnemonic phrase.
    Import {
        /// BIP-39 mnemonic phrase (supports 4-letter prefix expansion).
        #[arg(short, long)]
        mnemonic: String,

        #[command(flatten)]
        args: CosmosArgs,
    },
}

/// Cosmos-specific CLI flags (bech32 HRP + BIP-44 coin type).
#[derive(Args, Debug, Clone)]
struct CosmosArgs {
    /// Bech32 human-readable prefix (e.g. `cosmos`, `osmo`, `terra`).
    #[arg(long, default_value = "cosmos")]
    hrp: String,

    /// BIP-44 coin type (118 for Cosmos Hub/Osmosis, 330 for Terra, …).
    #[arg(long, default_value = "118")]
    coin_type: u32,

    #[command(flatten)]
    common: SimpleArgs,
}

impl CosmosCommand {
    pub(crate) fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        let (mnemonic, args) = match self.command {
            CosmosSubcommand::New { args } => (None, args),
            CosmosSubcommand::Import { mnemonic, args } => (Some(mnemonic), args),
        };
        let wallet = args.common.build_wallet(mnemonic.as_deref())?;

        let deriver = Deriver::with_config(&wallet, ChainConfig::new(args.hrp, args.coin_type));
        let accounts = deriver.derive_many(0, args.common.count)?;
        let out = HdWalletOutput::simple("cosmos", &wallet, &accounts);
        output::render_hd_wallet(&out, json, args.common.qr)?;
        Ok(())
    }
}
