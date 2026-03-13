//! Solana wallet CLI commands.

use clap::{Args, Subcommand, ValueEnum};
use kobe::Wallet;
use kobe_svm::{DerivationStyle, Deriver, StandardWallet};

use crate::output::{self, AccountOutput, HdWalletOutput, SingleKeyOutput};

/// CLI-compatible derivation style enum.
///
/// Maps to `kobe_svm::DerivationStyle` variants.
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

    /// Legacy: m/501'/{index}'/0'/0' (deprecated, old Phantom/Sollet)
    #[value(alias = "old")]
    Legacy,
}

#[allow(deprecated)]
impl From<CliDerivationStyle> for DerivationStyle {
    fn from(style: CliDerivationStyle) -> Self {
        match style {
            CliDerivationStyle::Standard => Self::Standard,
            CliDerivationStyle::Trust => Self::Trust,
            CliDerivationStyle::LedgerLive => Self::LedgerLive,
            CliDerivationStyle::Legacy => Self::Legacy,
        }
    }
}

/// Solana wallet operations.
#[derive(Args)]
pub struct SolanaCommand {
    /// The subcommand to execute.
    #[command(subcommand)]
    command: SolanaSubcommand,
}

/// Solana wallet subcommands.
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

        /// Number of accounts to derive.
        #[arg(short, long, default_value = "1")]
        count: u32,

        /// Derivation path style for wallet compatibility.
        #[arg(short, long, default_value = "standard")]
        style: CliDerivationStyle,

        /// Display QR code for each address.
        #[arg(long)]
        qr: bool,
    },

    /// Import wallet from private key.
    ImportKey {
        /// Private key in hex format.
        #[arg(short, long)]
        key: String,

        /// Display QR code for the address.
        #[arg(long)]
        qr: bool,
    },
}

impl SolanaCommand {
    /// Execute the Solana command.
    pub fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            SolanaSubcommand::New {
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
            SolanaSubcommand::Random { qr } => {
                let wallet = StandardWallet::generate()?;
                let out = build_single_key(&wallet);
                output::render_single_key(&out, json, qr)?;
            }
            SolanaSubcommand::Import {
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
            SolanaSubcommand::ImportKey { key, qr } => {
                let hex_key = key.strip_prefix("0x").unwrap_or(&key);
                let wallet = StandardWallet::from_hex(hex_key)?;
                let out = build_single_key(&wallet);
                output::render_single_key(&out, json, qr)?;
            }
        }
        Ok(())
    }
}

/// Build HD wallet output struct from SVM-specific types.
fn build_hd(
    wallet: &Wallet,
    style: DerivationStyle,
    addresses: &[kobe_svm::DerivedAddress],
) -> HdWalletOutput {
    HdWalletOutput {
        chain: "solana",
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
                private_key: a.keypair_base58.to_string(),
            })
            .collect(),
    }
}

/// Build single-key output struct from SVM StandardWallet.
fn build_single_key(wallet: &StandardWallet) -> SingleKeyOutput {
    SingleKeyOutput {
        chain: "solana",
        network: None,
        address_type: None,
        address: wallet.address(),
        private_key: wallet.keypair_base58().to_string(),
        public_key: wallet.pubkey_hex(),
    }
}
