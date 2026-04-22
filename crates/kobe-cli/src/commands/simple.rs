//! Shared command template for simple chains.
//!
//! Chains without network/address-type/style parameters (Aptos, Sui, Spark,
//! Filecoin, Tron, XRPL, TON, …) all expose the same `new` / `import`
//! surface. This module provides a single generic subcommand reused by each
//! chain's thin wrapper, eliminating hundreds of lines of boilerplate.

use clap::{Args, Subcommand};
use kobe::{DerivedAccount, Wallet};

use crate::output::{self, HdWalletOutput};

/// Boxed error alias returned by the CLI dispatch layer.
pub(crate) type CliResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Common flags shared by every simple chain's `new` / `import` command.
#[derive(Args, Debug, Clone)]
pub(crate) struct SimpleArgs {
    /// Number of mnemonic words (12, 15, 18, 21, or 24).
    #[arg(short, long, default_value_t = 12)]
    pub words: usize,

    /// Optional BIP-39 passphrase.
    #[arg(short, long)]
    pub passphrase: Option<String>,

    /// Number of addresses to derive.
    #[arg(short, long, default_value_t = 1)]
    pub count: u32,

    /// Display QR code for each derived address.
    #[arg(long)]
    pub qr: bool,
}

/// Subcommand template reused across all simple chain commands.
#[derive(Subcommand, Debug)]
pub(crate) enum SimpleSubcommand {
    /// Generate a new wallet (with mnemonic).
    New {
        #[command(flatten)]
        args: SimpleArgs,
    },
    /// Import wallet from mnemonic phrase.
    Import {
        /// BIP-39 mnemonic phrase (supports 4-letter prefix expansion).
        #[arg(short, long)]
        mnemonic: String,

        #[command(flatten)]
        args: SimpleArgs,
    },
}

impl SimpleSubcommand {
    /// Execute the subcommand, delegating to `derive_fn` for the chain-specific derivation.
    ///
    /// `derive_fn` receives the constructed wallet and the requested count,
    /// and returns the derived accounts. Wrapping avoids the HRTB limitation
    /// that prevents a bare `Deriver::new` function pointer from inferring
    /// its own lifetime in the generic signature.
    ///
    /// # Errors
    ///
    /// Returns an error if mnemonic expansion, wallet construction, or
    /// derivation fails.
    pub(crate) fn execute<F>(self, chain: &'static str, json: bool, derive_fn: F) -> CliResult
    where
        F: FnOnce(&Wallet, u32) -> CliResult<Vec<DerivedAccount>>,
    {
        let (wallet, args) = match self {
            Self::New { args } => {
                let wallet = Wallet::generate(args.words, args.passphrase.as_deref())?;
                (wallet, args)
            }
            Self::Import { mnemonic, args } => {
                let expanded = kobe::mnemonic::expand(&mnemonic)?;
                let wallet = Wallet::from_mnemonic(&expanded, args.passphrase.as_deref())?;
                (wallet, args)
            }
        };

        let accounts = derive_fn(&wallet, args.count)?;
        let out = HdWalletOutput::simple(chain, &wallet, &accounts);
        output::render_hd_wallet(&out, json, args.qr)?;
        Ok(())
    }
}
