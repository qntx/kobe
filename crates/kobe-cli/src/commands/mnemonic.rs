//! Mnemonic utility CLI commands (camouflage encrypt/decrypt).

use std::io::{self, BufRead};

use clap::{Args, Subcommand};

use crate::output::{self, CamouflageOutput};

/// Mnemonic utility operations.
#[derive(Args)]
pub(crate) struct MnemonicCommand {
    /// The subcommand to execute.
    #[command(subcommand)]
    command: MnemonicSubcommand,
}

/// Mnemonic utility subcommands.
#[derive(Subcommand)]
enum MnemonicSubcommand {
    /// Encrypt a mnemonic into a camouflaged (but valid) BIP-39 mnemonic.
    ///
    /// The output looks like a normal mnemonic and can even generate a
    /// real (empty) wallet. Only someone with the password can recover
    /// the original mnemonic.
    ///
    /// Pass `-m -` to read the mnemonic from stdin (avoids shell history).
    /// Phrases are hidden unless global `-r` / `--reveal` is set.
    Encrypt {
        /// BIP39 mnemonic phrase (`-` = read one line from stdin).
        #[arg(short, long)]
        mnemonic: String,

        /// Password used to derive the encryption key.
        #[arg(short, long)]
        password: String,
    },

    /// Decrypt a camouflaged mnemonic back to the original.
    ///
    /// Requires the same password that was used during encryption.
    ///
    /// Pass `-c -` to read the camouflaged phrase from stdin.
    /// Phrases are hidden unless global `-r` / `--reveal` is set.
    Decrypt {
        /// Camouflaged BIP-39 mnemonic phrase (`-` = read one line from stdin).
        #[arg(short = 'c', long)]
        camouflaged: String,

        /// Password used during encryption.
        #[arg(short, long)]
        password: String,
    },
}

impl MnemonicCommand {
    /// Execute the mnemonic command.
    ///
    /// # Errors
    ///
    /// Returns an error if expansion, camouflage crypto, or I/O fails.
    pub(crate) fn execute(
        self,
        json: bool,
        reveal: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            MnemonicSubcommand::Encrypt { mnemonic, password } => {
                let phrase = read_phrase_arg(&mnemonic, "mnemonic")?;
                let expanded = kobe::mnemonic::expand(&phrase)?;
                let camouflaged = kobe::camouflage::encrypt(&expanded, &password)?;
                let out = CamouflageOutput::new(
                    "encrypt",
                    expanded.split_whitespace().count(),
                    expanded,
                    camouflaged.to_string(),
                    reveal,
                );
                output::render_camouflage(&out, json)?;
            }
            MnemonicSubcommand::Decrypt {
                camouflaged,
                password,
            } => {
                let phrase = read_phrase_arg(&camouflaged, "camouflaged mnemonic")?;
                let expanded = kobe::mnemonic::expand(&phrase)?;
                let original = kobe::camouflage::decrypt(&expanded, &password)?;
                let out = CamouflageOutput::new(
                    "decrypt",
                    expanded.split_whitespace().count(),
                    expanded,
                    original.to_string(),
                    reveal,
                );
                output::render_camouflage(&out, json)?;
            }
        }
        Ok(())
    }
}

/// Resolve a phrase argument: literal string, or one stdin line when `-`.
fn read_phrase_arg(value: &str, label: &str) -> Result<String, Box<dyn std::error::Error>> {
    if value != "-" {
        return Ok(value.to_owned());
    }
    let mut line = String::new();
    let n = io::stdin().lock().read_line(&mut line)?;
    if n == 0 {
        return Err(format!("expected {label} on stdin, got EOF").into());
    }
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(format!("expected non-empty {label} on stdin").into());
    }
    Ok(trimmed.to_owned())
}
