//! Ethereum wallet CLI commands.

use clap::{Args, Subcommand, ValueEnum};
use kobe::Wallet;
use kobe_evm::{DerivationStyle, Deriver, StandardWallet};

use crate::output::{self, AccountOutput, HdWalletOutput, SingleKeyOutput};

/// Ethereum wallet operations.
#[derive(Args)]
pub struct EthereumCommand {
    /// The subcommand to execute.
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
            CliDerivationStyle::Standard => Self::Standard,
            CliDerivationStyle::LedgerLive => Self::LedgerLive,
            CliDerivationStyle::LedgerLegacy => Self::LedgerLegacy,
        }
    }
}

/// Ethereum wallet subcommands.
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
    pub fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            EthereumSubcommand::New {
                words,
                passphrase,
                count,
                style,
                qr,
            } => {
                let derivation_style = DerivationStyle::from(style);
                let wallet = Wallet::generate(words, passphrase.as_deref())?;
                let deriver = Deriver::new(&wallet);
                let addresses = deriver.derive_many_with(derivation_style, 0, count)?;
                let out = build_hd(&wallet, derivation_style, &addresses);
                output::render_hd_wallet(&out, json, qr)?;
            }
            EthereumSubcommand::Random { qr } => {
                let wallet = StandardWallet::generate()?;
                let out = build_single_key(&wallet);
                output::render_single_key(&out, json, qr)?;
            }
            EthereumSubcommand::Import {
                mnemonic,
                passphrase,
                count,
                style,
                qr,
            } => {
                let derivation_style = DerivationStyle::from(style);
                let expanded = kobe::mnemonic::expand(&mnemonic)?;
                let wallet = Wallet::from_mnemonic(&expanded, passphrase.as_deref())?;
                let deriver = Deriver::new(&wallet);
                let addresses = deriver.derive_many_with(derivation_style, 0, count)?;
                let out = build_hd(&wallet, derivation_style, &addresses);
                output::render_hd_wallet(&out, json, qr)?;
            }
            EthereumSubcommand::ImportKey { key, qr } => {
                let wallet = StandardWallet::from_hex(&key)?;
                let out = build_single_key(&wallet);
                output::render_single_key(&out, json, qr)?;
            }
        }
        Ok(())
    }
}

/// Build HD wallet output struct from EVM-specific types.
fn build_hd(
    wallet: &Wallet,
    style: DerivationStyle,
    addresses: &[kobe_evm::DerivedAddress],
) -> HdWalletOutput {
    HdWalletOutput {
        chain: "ethereum",
        network: None,
        address_type: None,
        mnemonic: wallet.mnemonic().to_string(),
        passphrase_protected: wallet.has_passphrase(),
        derivation_style: Some(style.name()),
        accounts: addresses
            .iter()
            .enumerate()
            .map(|(i, a)| AccountOutput {
                index: u32::try_from(i).unwrap_or(u32::MAX),
                derivation_path: a.path.clone(),
                address: a.address.clone(),
                private_key: format!("0x{}", a.private_key_hex.as_str()),
            })
            .collect(),
    }
}

/// Build single-key output struct from EVM StandardWallet.
fn build_single_key(wallet: &StandardWallet) -> SingleKeyOutput {
    SingleKeyOutput {
        chain: "ethereum",
        network: None,
        address_type: None,
        address: wallet.address(),
        private_key: format!("0x{}", wallet.secret_hex().as_str()),
        public_key: format!("0x{}", wallet.pubkey_hex()),
    }
}
