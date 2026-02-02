//! Bitcoin wallet CLI commands.

use clap::{Args, Subcommand, ValueEnum};
use colored::Colorize;
use kobe::Wallet;
use kobe_btc::{AddressType, Deriver, Network, StandardWallet};

/// Bitcoin wallet operations.
#[derive(Args)]
pub struct BitcoinCommand {
    #[command(subcommand)]
    command: BitcoinSubcommand,
}

#[derive(Subcommand)]
enum BitcoinSubcommand {
    /// Generate a new wallet (with mnemonic).
    New {
        /// Use testnet instead of mainnet.
        #[arg(short, long)]
        testnet: bool,

        /// Number of mnemonic words (12, 15, 18, 21, or 24).
        #[arg(short, long, default_value = "12")]
        words: usize,

        /// BIP39 passphrase (optional extra security).
        #[arg(short, long)]
        passphrase: Option<String>,

        /// Address type to generate.
        #[arg(short, long, value_enum, default_value = "native-segwit")]
        address_type: CliAddressType,

        /// Number of addresses to derive.
        #[arg(short, long, default_value = "1")]
        count: u32,

        /// Display QR code for each address.
        #[arg(long)]
        qr: bool,
    },

    /// Generate a random single-key wallet (no mnemonic).
    Random {
        /// Use testnet instead of mainnet.
        #[arg(short, long)]
        testnet: bool,

        /// Address type to generate.
        #[arg(short, long, value_enum, default_value = "native-segwit")]
        address_type: CliAddressType,

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

        /// Use testnet instead of mainnet.
        #[arg(short, long)]
        testnet: bool,

        /// Address type to generate.
        #[arg(short, long, value_enum, default_value = "native-segwit")]
        address_type: CliAddressType,

        /// Number of addresses to derive.
        #[arg(short, long, default_value = "1")]
        count: u32,

        /// Display QR code for each address.
        #[arg(long)]
        qr: bool,
    },

    /// Import wallet from private key (WIF format).
    ImportKey {
        /// Private key in WIF format.
        #[arg(short, long)]
        key: String,

        /// Address type to generate.
        #[arg(short, long, value_enum, default_value = "native-segwit")]
        address_type: CliAddressType,

        /// Display QR code for the address.
        #[arg(long)]
        qr: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum CliAddressType {
    /// Legacy P2PKH (starts with 1)
    Legacy,
    /// `SegWit` P2SH-P2WPKH (starts with 3)
    Segwit,
    /// Native `SegWit` P2WPKH (starts with bc1q)
    NativeSegwit,
    /// Taproot P2TR (starts with bc1p)
    Taproot,
}

impl From<CliAddressType> for AddressType {
    fn from(val: CliAddressType) -> Self {
        match val {
            CliAddressType::Legacy => Self::P2pkh,
            CliAddressType::Segwit => Self::P2shP2wpkh,
            CliAddressType::NativeSegwit => Self::P2wpkh,
            CliAddressType::Taproot => Self::P2tr,
        }
    }
}

impl BitcoinCommand {
    /// Execute the Bitcoin command.
    pub fn execute(self) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            BitcoinSubcommand::New {
                testnet,
                words,
                passphrase,
                address_type,
                count,
                qr,
            } => {
                let network = if testnet {
                    Network::Testnet
                } else {
                    Network::Mainnet
                };
                let addr_type = AddressType::from(address_type);
                let wallet = Wallet::generate(words, passphrase.as_deref())?;
                let deriver = Deriver::new(&wallet, network)?;
                print_wallet(&wallet, &deriver, addr_type, count, qr)?;
            }
            BitcoinSubcommand::Random {
                testnet,
                address_type,
                qr,
            } => {
                let network = if testnet {
                    Network::Testnet
                } else {
                    Network::Mainnet
                };
                let addr_type = AddressType::from(address_type);
                let wallet = StandardWallet::generate(network, addr_type)?;
                print_standard_wallet(&wallet, qr);
            }
            BitcoinSubcommand::Import {
                mnemonic,
                passphrase,
                testnet,
                address_type,
                count,
                qr,
            } => {
                let network = if testnet {
                    Network::Testnet
                } else {
                    Network::Mainnet
                };
                let addr_type = AddressType::from(address_type);
                let wallet = Wallet::from_mnemonic(&mnemonic, passphrase.as_deref())?;
                let deriver = Deriver::new(&wallet, network)?;
                print_wallet(&wallet, &deriver, addr_type, count, qr)?;
            }
            BitcoinSubcommand::ImportKey {
                key,
                address_type,
                qr,
            } => {
                let addr_type = AddressType::from(address_type);
                let wallet = StandardWallet::from_wif(&key, addr_type)?;
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
    address_type: AddressType,
    count: u32,
    show_qr: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let network_str = match deriver.network() {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
    };
    let addresses = deriver.derive_many_with(address_type, 0, count)?;

    println!();
    println!("      {}      {}", "Network".cyan().bold(), network_str);
    println!("      {} {}", "Address Type".cyan().bold(), address_type.name());
    println!("      {}     {}", "Mnemonic".cyan().bold(), wallet.mnemonic());
    if wallet.has_passphrase() {
        println!("      {}   {}", "Passphrase".cyan().bold(), "(set)".dimmed());
    }
    println!();

    for (i, addr) in addresses.iter().enumerate() {
        if count > 1 {
            println!("      {}        {}", "Index".cyan().bold(), format!("[{i}]").dimmed());
        }
        println!("      {}         {}", "Path".cyan().bold(), addr.path);
        println!("      {}      {}", "Address".cyan().bold(), addr.address.green());
        println!("      {}  {}", "Private Key".cyan().bold(), addr.private_key_wif.as_str());
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
    let network_str = match wallet.network() {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
    };

    println!();
    println!("      {}      {}", "Network".cyan().bold(), network_str);
    println!("      {} {}", "Address Type".cyan().bold(), wallet.address_type().name());
    println!("      {}      {}", "Address".cyan().bold(), wallet.address().green());
    println!("      {}  {}", "Private Key".cyan().bold(), wallet.to_wif().as_str());
    println!("      {}   {}", "Public Key".cyan().bold(), wallet.pubkey_hex().dimmed());
    if show_qr {
        crate::qr::render_to_terminal(&wallet.address());
    }
    println!();
}
