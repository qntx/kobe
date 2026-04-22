//! TON wallet CLI commands.

use clap::Args;
use kobe::ton::Deriver;

use crate::commands::SimpleSubcommand;

/// TON wallet operations.
#[derive(Args, Debug)]
pub(crate) struct TonCommand {
    #[command(subcommand)]
    command: SimpleSubcommand,
}

impl TonCommand {
    pub(crate) fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        self.command
            .execute("ton", json, |w, n| Ok(Deriver::new(w).derive_many(0, n)?))
    }
}
