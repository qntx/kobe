//! Nostr wallet CLI commands.

use clap::Args;
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
        self.command
            .execute("nostr", json, |w, n| Ok(Deriver::new(w).derive_many(0, n)?))
    }
}
