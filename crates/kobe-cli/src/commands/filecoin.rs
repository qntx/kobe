//! Filecoin wallet CLI commands.

use clap::Args;
use kobe::fil::Deriver;

use crate::commands::SimpleSubcommand;

/// Filecoin wallet operations.
#[derive(Args, Debug)]
pub(crate) struct FilecoinCommand {
    #[command(subcommand)]
    command: SimpleSubcommand,
}

impl FilecoinCommand {
    pub(crate) fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        self.command.execute("filecoin", json, |w, n| {
            Ok(Deriver::new(w).derive_many(0, n)?)
        })
    }
}
