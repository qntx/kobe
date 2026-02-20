//! Ethereum wallet CLI commands.

use clap::{Args, Subcommand, ValueEnum};
use colored::Colorize;
use kobe::Wallet;
use kobe_evm::{DerivationStyle, Deriver, StandardWallet};

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

        /// Display QR code for each address.
        #[arg(long)]
        qr: bool,
    },

    /// Generate a random single-key wallet (no mnemonic).
    Random {
        /// Display QR code for the address.
        #[arg(long)]
        qr: bool,
    },

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

        /// Display QR code for each address.
        #[arg(long)]
        qr: bool,
    },

    /// Import wallet from private key.
    ImportKey {
        /// Private key in hex format (with or without 0x prefix).
        #[arg(short, long)]
        key: String,

        /// Display QR code for the address.
        #[arg(long)]
        qr: bool,
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
                qr,
            } => {
                let wallet = Wallet::generate(words, passphrase.as_deref())?;
                let deriver = Deriver::new(&wallet);
                print_wallet(&wallet, &deriver, count, style.into(), qr)?;
            }
            EthereumSubcommand::Random { qr } => {
                let wallet = StandardWallet::generate()?;
                print_standard_wallet(&wallet, qr);
            }
            EthereumSubcommand::Import {
                mnemonic,
                passphrase,
                count,
                style,
                qr,
            } => {
                let mnemonic = kobe::mnemonic::expand(&mnemonic)?;
                let wallet = Wallet::from_mnemonic(&mnemonic, passphrase.as_deref())?;
                let deriver = Deriver::new(&wallet);
                print_wallet(&wallet, &deriver, count, style.into(), qr)?;
            }
            EthereumSubcommand::ImportKey { key, qr } => {
                let wallet = StandardWallet::from_hex(&key)?;
                print_standard_wallet(&wallet, qr);
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
    show_qr: bool,
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
        if show_qr {
            crate::qr::render_to_terminal(&addr.address);
        }
        if i < addresses.len() - 1 {
            println!();
        }
    }
    println!();

    Ok(())
}

#[rustfmt::skip]
fn print_standard_wallet(wallet: &StandardWallet, show_qr: bool) {
    println!();
    println!("      {}      {}", "Address".cyan().bold(), wallet.address().green());
    println!("      {}  0x{}", "Private Key".cyan().bold(), wallet.secret_hex().as_str());
    println!("      {}   0x{}", "Public Key".cyan().bold(), wallet.pubkey_hex().dimmed());
    if show_qr {
        crate::qr::render_to_terminal(&wallet.address());
    }
    println!();
}
