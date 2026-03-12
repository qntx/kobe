//! Mnemonic utility CLI commands (camouflage encrypt/decrypt).

use clap::{Args, Subcommand};

use crate::output::{self, CamouflageOutput};

/// Mnemonic utility operations.
#[derive(Args)]
pub struct MnemonicCommand {
    #[command(subcommand)]
    command: MnemonicSubcommand,
}

#[derive(Subcommand)]
enum MnemonicSubcommand {
    /// Encrypt a mnemonic into a camouflaged (but valid) BIP-39 mnemonic.
    ///
    /// The output looks like a normal mnemonic and can even generate a
    /// real (empty) wallet. Only someone with the password can recover
    /// the original mnemonic.
    Encrypt {
        /// BIP39 mnemonic phrase to camouflage.
        #[arg(short, long)]
        mnemonic: String,

        /// Password used to derive the encryption key.
        #[arg(short, long)]
        password: String,
    },

    /// Decrypt a camouflaged mnemonic back to the original.
    ///
    /// Requires the same password that was used during encryption.
    Decrypt {
        /// Camouflaged BIP-39 mnemonic phrase.
        #[arg(short = 'c', long)]
        camouflaged: String,

        /// Password used during encryption.
        #[arg(short, long)]
        password: String,
    },
}

impl MnemonicCommand {
    /// Execute the mnemonic command.
    pub fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            MnemonicSubcommand::Encrypt { mnemonic, password } => {
                let mnemonic = kobe::mnemonic::expand(&mnemonic)?;
                let camouflaged = kobe::camouflage::encrypt(&mnemonic, &password)?;
                let out = CamouflageOutput {
                    mode: "encrypt",
                    words: mnemonic.split_whitespace().count(),
                    input: mnemonic,
                    output: camouflaged.to_string(),
                };
                output::render_camouflage(&out, json)?;
            }
            MnemonicSubcommand::Decrypt {
                camouflaged,
                password,
            } => {
                let camouflaged = kobe::mnemonic::expand(&camouflaged)?;
                let original = kobe::camouflage::decrypt(&camouflaged, &password)?;
                let out = CamouflageOutput {
                    mode: "decrypt",
                    words: camouflaged.split_whitespace().count(),
                    input: camouflaged.to_string(),
                    output: original.to_string(),
                };
                output::render_camouflage(&out, json)?;
            }
        }
        Ok(())
    }
}
