//! Spark wallet CLI commands.

use clap::Args;
use kobe::DeriveExt;
use kobe::spark::Deriver;

use crate::commands::SimpleSubcommand;

/// Spark (Bitcoin L2) wallet operations.
#[derive(Args, Debug)]
pub(crate) struct SparkCommand {
    #[command(subcommand)]
    command: SimpleSubcommand,
}

impl SparkCommand {
    pub(crate) fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        self.command
            .execute("spark", json, |w, n| Ok(Deriver::new(w).derive_many(0, n)?))
    }
}
