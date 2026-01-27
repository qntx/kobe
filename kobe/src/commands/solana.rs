//! Solana wallet CLI commands.

use clap::{Args, Subcommand};
use colored::Colorize;
use kobe_core::Wallet;
use kobe_sol::{Deriver, StandardWallet};

/// Solana wallet operations.
#[derive(Args)]
pub struct SolanaCommand {
    #[command(subcommand)]
    command: SolanaSubcommand,
}

#[derive(Subcommand)]
enum SolanaSubcommand {
    /// Generate a new wallet (with mnemonic).
    New {
        /// Number of mnemonic words (12, 15, 18, 21, or 24).
        #[arg(short, long, default_value = "12")]
        words: usize,

        /// BIP39 passphrase (optional extra security).
        #[arg(short, long)]
        passphrase: Option<String>,

        /// Number of accounts to derive.
        #[arg(short, long, default_value = "1")]
        count: u32,
    },

    /// Generate a random single-key wallet (no mnemonic).
    Random,

    /// Import wallet from mnemonic phrase.
    Import {
        /// BIP39 mnemonic phrase.
        #[arg(short, long)]
        mnemonic: String,

        /// BIP39 passphrase (if used when creating).
        #[arg(short, long)]
        passphrase: Option<String>,

        /// Number of accounts to derive.
        #[arg(short, long, default_value = "1")]
        count: u32,
    },

    /// Import wallet from private key.
    ImportKey {
        /// Private key in hex format.
        #[arg(short, long)]
        key: String,
    },
}

impl SolanaCommand {
    /// Execute the Solana command.
    pub fn execute(self) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            SolanaSubcommand::New {
                words,
                passphrase,
                count,
            } => {
                let wallet = Wallet::generate(words, passphrase.as_deref())?;
                let deriver = Deriver::new(&wallet);
                print_wallet(&wallet, &deriver, count)?;
            }
            SolanaSubcommand::Random => {
                let wallet = StandardWallet::generate()?;
                print_standard_wallet(&wallet);
            }
            SolanaSubcommand::Import {
                mnemonic,
                passphrase,
                count,
            } => {
                let wallet = Wallet::from_mnemonic(&mnemonic, passphrase.as_deref())?;
                let deriver = Deriver::new(&wallet);
                print_wallet(&wallet, &deriver, count)?;
            }
            SolanaSubcommand::ImportKey { key } => {
                let key = key.strip_prefix("0x").unwrap_or(&key);
                let wallet = StandardWallet::from_private_key_hex(key)?;
                print_standard_wallet(&wallet);
            }
        }
        Ok(())
    }
}

#[rustfmt::skip]
fn print_wallet(
    wallet: &Wallet,
    deriver: &Deriver,
    count: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let addresses = deriver.derive_many(0, count)?;

    println!();
    println!("      {}     {}", "Mnemonic".cyan().bold(), wallet.mnemonic());
    if wallet.has_passphrase() {
        println!("      {}   {}", "Passphrase".cyan().bold(), "(set)".dimmed());
    }
    println!();

    for (i, addr) in addresses.iter().enumerate() {
        if count > 1 {
            println!("      {}      {}", "Account".cyan().bold(), format!("[{}]", i).dimmed());
        }
        println!("      {}         {}", "Path".cyan().bold(), addr.path);
        println!("      {}      {}", "Address".cyan().bold(), addr.address.green());
        println!("      {}  {}", "Private Key".cyan().bold(), addr.private_key_hex.as_str());
        if i < addresses.len() - 1 {
            println!();
        }
    }
    println!();

    Ok(())
}

#[rustfmt::skip]
fn print_standard_wallet(wallet: &StandardWallet) {
    println!();
    println!("      {}      {}", "Address".cyan().bold(), wallet.address_string().green());
    println!("      {}  {}", "Private Key".cyan().bold(), wallet.private_key_hex().as_str());
    println!("      {}   {}", "Public Key".cyan().bold(), wallet.public_key_hex().dimmed());
    println!();
}
