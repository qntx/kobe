//! Nostr wallet CLI commands (NIP-06 / NIP-19).

use clap::Args;
use kobe::DeriveExt;
use kobe::nostr::Deriver;

use crate::commands::SimpleSubcommand;

/// Nostr wallet operations (NIP-06 / NIP-19).
#[derive(Args, Debug)]
pub(crate) struct NostrCommand {
    #[command(subcommand)]
    command: SimpleSubcommand,
}

impl NostrCommand {
    pub(crate) fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        self.command.execute_with(
            "nostr",
            json,
            |w, n| Ok(Deriver::new(w).derive_many(0, n)?),
            |a| a.nsec().as_str().to_owned(),
        )
    }
}
