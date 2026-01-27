//! Ethereum wallet CLI commands.

use clap::{Args, Subcommand};
use colored::Colorize;
use kobe_core::Wallet;
use kobe_eth::{Deriver, StandardWallet};

/// Ethereum wallet operations.
#[derive(Args)]
pub struct EthereumCommand {
    #[command(subcommand)]
    command: EthereumSubcommand,
}

#[derive(Subcommand)]
enum EthereumSubcommand {
    /// Generate a new wallet (with mnemonic).
    New {
        /// Number of mnemonic words (12, 15, 18, 21, or 24).
        #[arg(short, long, default_value = "12")]
        words: usize,

        /// BIP39 passphrase (optional extra security).
        #[arg(short, long)]
        passphrase: Option<String>,

        /// Number of addresses to derive.
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

        /// Number of addresses to derive.
        #[arg(short, long, default_value = "1")]
        count: u32,
    },

    /// Import wallet from private key.
    ImportKey {
        /// Private key in hex format (with or without 0x prefix).
        #[arg(short, long)]
        key: String,
    },
}

impl EthereumCommand {
    /// Execute the Ethereum command.
    pub fn execute(self) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            EthereumSubcommand::New {
                words,
                passphrase,
                count,
            } => {
                let wallet = Wallet::generate(words, passphrase.as_deref())?;
                let deriver = Deriver::new(&wallet);
                print_wallet(&wallet, &deriver, count)?;
            }
            EthereumSubcommand::Random => {
                let wallet = StandardWallet::generate()?;
                print_standard_wallet(&wallet);
            }
            EthereumSubcommand::Import {
                mnemonic,
                passphrase,
                count,
            } => {
                let wallet = Wallet::from_mnemonic(&mnemonic, passphrase.as_deref())?;
                let deriver = Deriver::new(&wallet);
                print_wallet(&wallet, &deriver, count)?;
            }
            EthereumSubcommand::ImportKey { key } => {
                let wallet = StandardWallet::from_private_key_hex(&key)?;
                print_standard_wallet(&wallet);
            }
        }
        Ok(())
    }
}

fn print_wallet(
    wallet: &Wallet,
    deriver: &Deriver,
    count: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    println!();
    println!("{}", "━".repeat(70).dimmed());
    println!("{}", " Ethereum Wallet ".bold().on_magenta());
    println!("{}", "━".repeat(70).dimmed());
    println!();
    if wallet.has_passphrase() {
        println!("  {}", "(with passphrase)".dimmed());
    }
    println!("{}", "Mnemonic:".bold());
    println!("  {}", wallet.mnemonic().yellow());
    println!();

    let addresses = deriver.derive_many(0, false, 0, count)?;

    for (i, addr) in addresses.iter().enumerate() {
        println!("{} #{}", "Address".bold(), i);
        println!("  {}: {}", "Path".dimmed(), addr.path);
        println!("  {}: {}", "Address".dimmed(), addr.address.green());
        println!(
            "  {}: 0x{}",
            "Private Key".dimmed(),
            addr.private_key_hex.as_str().red()
        );
        println!();
    }

    println!("{}", "━".repeat(70).dimmed());
    println!(
        "{}",
        "⚠ Store your mnemonic safely! Never share your private key!"
            .yellow()
            .bold()
    );
    println!("{}", "━".repeat(70).dimmed());
    println!();

    Ok(())
}

fn print_standard_wallet(wallet: &StandardWallet) {
    println!();
    println!("{}", "━".repeat(70).dimmed());
    println!("{}", " Ethereum Random Wallet ".bold().on_magenta());
    println!("{}", "━".repeat(70).dimmed());
    println!();
    println!("{}", "Private Key:".bold());
    println!("  0x{}", wallet.private_key_hex().as_str().red());
    println!();
    println!("{}", "Public Key:".bold());
    println!("  0x{}", wallet.public_key_hex().dimmed());
    println!();
    println!("{}", "Address:".bold());
    println!("  {}", wallet.address_string().green());
    println!();
    println!("{}", "━".repeat(70).dimmed());
    println!(
        "{}",
        "⚠ Back up your private key! There is no mnemonic for this wallet!"
            .yellow()
            .bold()
    );
    println!("{}", "━".repeat(70).dimmed());
    println!();
}
