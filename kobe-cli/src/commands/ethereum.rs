//! Ethereum wallet CLI commands.

use clap::{Args, Subcommand, ValueEnum};
use colored::Colorize;
use kobe::Wallet;
use kobe_eth::{DerivationStyle, Deriver, StandardWallet};

/// Ethereum wallet operations.
#[derive(Args)]
pub struct EthereumCommand {
    #[command(subcommand)]
    command: EthereumSubcommand,
}

/// CLI-compatible derivation style enum.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum CliDerivationStyle {
    /// Standard BIP-44 path (MetaMask/Trezor): m/44'/60'/0'/0/{index}
    #[default]
    Standard,
    /// Ledger Live path: m/44'/60'/{index}'/0/0
    #[value(name = "ledger-live")]
    LedgerLive,
    /// Ledger Legacy path (MEW/MyCrypto): m/44'/60'/0'/{index}
    #[value(name = "ledger-legacy")]
    LedgerLegacy,
}

impl From<CliDerivationStyle> for DerivationStyle {
    fn from(style: CliDerivationStyle) -> Self {
        match style {
            CliDerivationStyle::Standard => DerivationStyle::Standard,
            CliDerivationStyle::LedgerLive => DerivationStyle::LedgerLive,
            CliDerivationStyle::LedgerLegacy => DerivationStyle::LedgerLegacy,
        }
    }
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

        /// Derivation path style for hardware wallet compatibility.
        #[arg(short, long, default_value = "standard")]
        style: CliDerivationStyle,
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

        /// Derivation path style for hardware wallet compatibility.
        #[arg(short, long, default_value = "standard")]
        style: CliDerivationStyle,
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
                style,
            } => {
                let wallet = Wallet::generate(words, passphrase.as_deref())?;
                let deriver = Deriver::new(&wallet);
                print_wallet(&wallet, &deriver, count, style.into())?;
            }
            EthereumSubcommand::Random => {
                let wallet = StandardWallet::generate()?;
                print_standard_wallet(&wallet);
            }
            EthereumSubcommand::Import {
                mnemonic,
                passphrase,
                count,
                style,
            } => {
                let wallet = Wallet::from_mnemonic(&mnemonic, passphrase.as_deref())?;
                let deriver = Deriver::new(&wallet);
                print_wallet(&wallet, &deriver, count, style.into())?;
            }
            EthereumSubcommand::ImportKey { key } => {
                let wallet = StandardWallet::from_private_key_hex(&key)?;
                print_standard_wallet(&wallet);
            }
        }
        Ok(())
    }
}

#[rustfmt::skip]
fn print_wallet(
    wallet: &Wallet,
    deriver: &Deriver<'_>,
    count: u32,
    style: DerivationStyle,
) -> Result<(), Box<dyn std::error::Error>> {
    let addresses = deriver.derive_many_with(style, 0, count)?;

    println!();
    println!("      {}     {}", "Mnemonic".cyan().bold(), wallet.mnemonic());
    if wallet.has_passphrase() {
        println!("      {}   {}", "Passphrase".cyan().bold(), "(set)".dimmed());
    }
    println!("      {}        {}", "Style".cyan().bold(), style.name().dimmed());
    println!();

    for (i, addr) in addresses.iter().enumerate() {
        if count > 1 {
            println!("      {}        {}", "Index".cyan().bold(), format!("[{i}]").dimmed());
        }
        println!("      {}         {}", "Path".cyan().bold(), addr.path);
        println!("      {}      {}", "Address".cyan().bold(), addr.address.green());
        println!("      {}  0x{}", "Private Key".cyan().bold(), addr.private_key_hex.as_str());
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
    println!("      {}  0x{}", "Private Key".cyan().bold(), wallet.private_key_hex().as_str());
    println!("      {}   0x{}", "Public Key".cyan().bold(), wallet.public_key_hex().dimmed());
    println!();
}
