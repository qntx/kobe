//! Aptos wallet CLI commands.

use clap::Args;
use kobe::aptos::Deriver;

use crate::commands::SimpleSubcommand;

/// Aptos wallet operations.
#[derive(Args, Debug)]
pub(crate) struct AptosCommand {
    #[command(subcommand)]
    command: SimpleSubcommand,
}

impl AptosCommand {
    pub(crate) fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        self.command
            .execute("aptos", json, |w, n| Ok(Deriver::new(w).derive_many(0, n)?))
    }
}
