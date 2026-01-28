//! Solana wallet CLI commands.

use clap::{Args, Subcommand, ValueEnum};
use colored::Colorize;
use kobe_core::Wallet;
use kobe_sol::{DerivationStyle, Deriver, StandardWallet};

/// CLI-compatible derivation style enum.
///
/// Maps to `kobe_sol::DerivationStyle` variants.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum CliDerivationStyle {
    /// Standard: m/44'/501'/{index}'/0' (Phantom, Backpack, Solflare)
    #[default]
    #[value(alias = "phantom", alias = "backpack")]
    Standard,

    /// Trust: m/44'/501'/{index}' (Trust Wallet, Ledger, Keystone)
    #[value(alias = "ledger", alias = "keystone")]
    Trust,

    /// Ledger Live: m/44'/501'/{index}'/0'/0'
    LedgerLive,

    /// Legacy: m/501'/{index}'/0/0 (deprecated, old Phantom/Sollet)
    #[value(alias = "old")]
    Legacy,
}

#[allow(deprecated)]
impl From<CliDerivationStyle> for DerivationStyle {
    fn from(style: CliDerivationStyle) -> Self {
        match style {
            CliDerivationStyle::Standard => DerivationStyle::Standard,
            CliDerivationStyle::Trust => DerivationStyle::Trust,
            CliDerivationStyle::LedgerLive => DerivationStyle::LedgerLive,
            CliDerivationStyle::Legacy => DerivationStyle::Legacy,
        }
    }
}

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

        /// Derivation path style for wallet compatibility.
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

        /// Number of accounts to derive.
        #[arg(short, long, default_value = "1")]
        count: u32,

        /// Derivation path style for wallet compatibility.
        #[arg(short, long, default_value = "standard")]
        style: CliDerivationStyle,
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
                style,
            } => {
                let wallet = Wallet::generate(words, passphrase.as_deref())?;
                let deriver = Deriver::new(&wallet);
                print_wallet(&wallet, &deriver, count, style.into())?;
            }
            SolanaSubcommand::Random => {
                let wallet = StandardWallet::generate()?;
                print_standard_wallet(&wallet);
            }
            SolanaSubcommand::Import {
                mnemonic,
                passphrase,
                count,
                style,
            } => {
                let wallet = Wallet::from_mnemonic(&mnemonic, passphrase.as_deref())?;
                let deriver = Deriver::new(&wallet);
                print_wallet(&wallet, &deriver, count, style.into())?;
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
    style: DerivationStyle,
) -> Result<(), Box<dyn std::error::Error>> {
    let addresses = deriver.derive_many_with_style(style, 0, count)?;

    println!();
    println!("      {}     {}", "Mnemonic".cyan().bold(), wallet.mnemonic());
    if wallet.has_passphrase() {
        println!("      {}   {}", "Passphrase".cyan().bold(), "(set)".dimmed());
    }
    println!("      {}        {}", "Style".cyan().bold(), style.name().dimmed());
    println!();

    for (i, addr) in addresses.iter().enumerate() {
        if count > 1 {
            println!("      {}      {}", "Account".cyan().bold(), format!("[{i}]").dimmed());
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
