//! Tron wallet CLI commands.

use clap::Args;
use kobe::DeriveExt;
use kobe::tron::Deriver;

use crate::commands::SimpleSubcommand;

/// Tron wallet operations.
#[derive(Args, Debug)]
pub(crate) struct TronCommand {
    #[command(subcommand)]
    command: SimpleSubcommand,
}

impl TronCommand {
    pub(crate) fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        self.command
            .execute("tron", json, |w, n| Ok(Deriver::new(w).derive_many(0, n)?))
    }
}
