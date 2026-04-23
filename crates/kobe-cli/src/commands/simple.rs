//! Shared command template for simple chains.
//!
//! Chains without network/address-type/style parameters (Aptos, Sui, Spark,
//! Filecoin, Tron, XRPL, TON, Nostr, …) all expose the same `new` / `import`
//! surface. This module provides a single generic subcommand reused by each
//! chain's thin wrapper, eliminating hundreds of lines of boilerplate.

use clap::{Args, Subcommand};
use kobe::{DerivedAccount, Wallet};

use crate::output::{self, AccountOutput, HdWalletOutput};

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
    /// Execute the subcommand for chains whose CLI output uses the default
    /// hex-encoded private key format. Thin wrapper over
    /// [`execute_with`](Self::execute_with).
    ///
    /// # Errors
    ///
    /// Returns an error if mnemonic expansion, wallet construction, or
    /// derivation fails.
    pub(crate) fn execute<F>(self, chain: &'static str, json: bool, derive_fn: F) -> CliResult
    where
        F: FnOnce(&Wallet, u32) -> CliResult<Vec<DerivedAccount>>,
    {
        self.execute_with(chain, json, derive_fn, |a| {
            a.private_key_hex().as_str().to_owned()
        })
    }

    /// Execute the subcommand against a chain-specific account type, with
    /// a custom closure that formats each account's private key for display.
    ///
    /// Used by chains whose "private key" display format differs from the
    /// shared hex encoding (e.g. Nostr's NIP-19 `nsec`, Solana's base58
    /// keypair, Bitcoin's WIF).
    ///
    /// # Errors
    ///
    /// Returns an error if mnemonic expansion, wallet construction, derivation,
    /// or rendering fails.
    pub(crate) fn execute_with<A, F, G>(
        self,
        chain: &'static str,
        json: bool,
        derive_fn: F,
        format_private_key: G,
    ) -> CliResult
    where
        A: AsRef<DerivedAccount>,
        F: FnOnce(&Wallet, u32) -> CliResult<Vec<A>>,
        G: Fn(&A) -> String,
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
        let out = HdWalletOutput {
            chain,
            network: None,
            address_type: None,
            mnemonic: wallet.mnemonic().to_owned(),
            passphrase_protected: wallet.has_passphrase(),
            derivation_style: None,
            accounts: accounts
                .iter()
                .enumerate()
                .map(|(i, a)| {
                    let da = a.as_ref();
                    AccountOutput {
                        index: u32::try_from(i).unwrap_or(u32::MAX),
                        derivation_path: da.path().to_owned(),
                        address: da.address().to_owned(),
                        private_key: format_private_key(a),
                    }
                })
                .collect(),
        };
        output::render_hd_wallet(&out, json, args.qr)?;
        Ok(())
    }
}
