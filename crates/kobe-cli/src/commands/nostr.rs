//! Nostr wallet CLI commands (NIP-06 / NIP-19).

use clap::{Args, Subcommand};
use kobe::nostr::{Deriver, account_nsec};
use kobe::{DerivedAccount, Wallet};

use crate::commands::simple::SimpleArgs;
use crate::output::{self, HdWalletOutput};

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
        let out = build_hd(&wallet, &accounts)?;
        output::render_hd_wallet(&out, json, args.qr)?;
        Ok(())
    }
}

/// Build the `HdWalletOutput` with `nsec`-formatted private keys for display.
fn build_hd(
    wallet: &Wallet,
    accounts: &[DerivedAccount],
) -> Result<HdWalletOutput, Box<dyn std::error::Error>> {
    let mut out = HdWalletOutput::simple("nostr", wallet, accounts);
    for (slot, account) in out.accounts.iter_mut().zip(accounts.iter()) {
        account_nsec(account)?
            .as_str()
            .clone_into(&mut slot.private_key);
    }
    Ok(out)
}
