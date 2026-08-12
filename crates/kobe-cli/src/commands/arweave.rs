//! Arweave ECDSA wallet CLI commands.

use clap::Args;
use kobe::DeriveExt;
use kobe::arweave::Deriver;

use crate::commands::SimpleSubcommand;

/// Arweave ECDSA wallet operations (SLIP-44 coin type 472).
#[derive(Args, Debug)]
pub(crate) struct ArweaveCommand {
    #[command(subcommand)]
    command: SimpleSubcommand,
}

impl ArweaveCommand {
    pub(crate) fn execute(
        self,
        json: bool,
        reveal: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.command.execute("arweave", json, reveal, |w, n| {
            Ok(Deriver::new(w).derive_many(0, n)?)
        })
    }
}
