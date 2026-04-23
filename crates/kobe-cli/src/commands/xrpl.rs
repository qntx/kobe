//! XRPL wallet CLI commands.

use clap::Args;
use kobe::DeriveExt;
use kobe::xrpl::Deriver;

use crate::commands::SimpleSubcommand;

/// XRP Ledger wallet operations.
#[derive(Args, Debug)]
pub(crate) struct XrplCommand {
    #[command(subcommand)]
    command: SimpleSubcommand,
}

impl XrplCommand {
    pub(crate) fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        self.command
            .execute("xrpl", json, |w, n| Ok(Deriver::new(w).derive_many(0, n)?))
    }
}
