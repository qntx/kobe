//! Sui wallet CLI commands.

use clap::Args;
use kobe::DeriveExt;
use kobe::sui::Deriver;

use crate::commands::SimpleSubcommand;

/// Sui wallet operations.
#[derive(Args, Debug)]
pub(crate) struct SuiCommand {
    #[command(subcommand)]
    command: SimpleSubcommand,
}

impl SuiCommand {
    pub(crate) fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        self.command
            .execute("sui", json, |w, n| Ok(Deriver::new(w).derive_many(0, n)?))
    }
}
