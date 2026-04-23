//! Nostr wallet CLI commands (NIP-06 / NIP-19).

use clap::{Args, Subcommand};
use kobe::nostr::{Deriver, NostrAccount};
use kobe::{DeriveExt, Wallet};

use crate::commands::simple::SimpleArgs;
use crate::output::{self, AccountOutput, HdWalletOutput};

/// Nostr wallet operations (NIP-06 / NIP-19).
#[derive(Args, Debug)]
pub(crate) struct NostrCommand {
    #[command(subcommand)]
    command: NostrSubcommand,
}

#[derive(Subcommand, Debug)]
enum NostrSubcommand {
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

impl NostrCommand {
    pub(crate) fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        let (wallet, args) = match self.command {
            NostrSubcommand::New { args } => {
                let wallet = Wallet::generate(args.words, args.passphrase.as_deref())?;
                (wallet, args)
            }
            NostrSubcommand::Import { mnemonic, args } => {
                let expanded = kobe::mnemonic::expand(&mnemonic)?;
                let wallet = Wallet::from_mnemonic(&expanded, args.passphrase.as_deref())?;
                (wallet, args)
            }
        };

        let accounts = Deriver::new(&wallet).derive_many(0, args.count)?;
        let out = build_hd(&wallet, &accounts);
        output::render_hd_wallet(&out, json, args.qr)?;
        Ok(())
    }
}

/// Build the `HdWalletOutput` with `nsec`-formatted private keys for display.
fn build_hd(wallet: &Wallet, accounts: &[NostrAccount]) -> HdWalletOutput {
    HdWalletOutput {
        chain: "nostr",
        network: None,
        address_type: None,
        mnemonic: wallet.mnemonic().to_owned(),
        passphrase_protected: wallet.has_passphrase(),
        derivation_style: None,
        accounts: accounts
            .iter()
            .enumerate()
            .map(|(i, a)| AccountOutput {
                index: u32::try_from(i).unwrap_or(u32::MAX),
                derivation_path: a.path().to_owned(),
                address: a.address().to_owned(),
                private_key: a.nsec().as_str().to_owned(),
            })
            .collect(),
    }
}
