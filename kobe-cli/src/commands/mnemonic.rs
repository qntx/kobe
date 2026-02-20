//! Mnemonic utility CLI commands (camouflage encrypt/decrypt).

use clap::{Args, Subcommand};
use colored::Colorize;

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
    pub fn execute(self) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            MnemonicSubcommand::Encrypt { mnemonic, password } => {
                let camouflaged = kobe::camouflage::encrypt(&mnemonic, &password)?;
                print_encrypt_result(&mnemonic, &camouflaged);
            }
            MnemonicSubcommand::Decrypt {
                camouflaged,
                password,
            } => {
                let original = kobe::camouflage::decrypt(&camouflaged, &password)?;
                print_decrypt_result(&camouflaged, &original);
            }
        }
        Ok(())
    }
}

/// Display the encrypt (camouflage) result.
#[rustfmt::skip]
fn print_encrypt_result(original: &str, camouflaged: &str) {
    let words = original.split_whitespace().count();

    println!();
    println!("      {}         {}", "Mode".cyan().bold(), "Encrypt");
    println!("      {}        {words} words", "Words".cyan().bold());
    println!("      {}     {}", "Original".cyan().bold(), original);
    println!("      {}  {}", "Camouflaged".cyan().bold(), camouflaged.green());
    println!();
}

/// Display the decrypt (recover) result.
#[rustfmt::skip]
fn print_decrypt_result(camouflaged: &str, recovered: &str) {
    let words = camouflaged.split_whitespace().count();

    println!();
    println!("      {}         {}", "Mode".cyan().bold(), "Decrypt");
    println!("      {}        {words} words", "Words".cyan().bold());
    println!("      {}  {}", "Camouflaged".cyan().bold(), camouflaged);
    println!("      {}    {}", "Recovered".cyan().bold(), recovered.green());
    println!();
}
