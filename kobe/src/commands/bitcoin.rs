//! Bitcoin wallet CLI commands.

use clap::{Args, Subcommand, ValueEnum};
use colored::Colorize;
use kobe_btc::{AddressType, Deriver, Network, StandardWallet};
use kobe_core::Wallet;

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
    },

    /// Generate a random single-key wallet (no mnemonic).
    Random {
        /// Use testnet instead of mainnet.
        #[arg(short, long)]
        testnet: bool,

        /// Address type to generate.
        #[arg(short, long, value_enum, default_value = "native-segwit")]
        address_type: CliAddressType,
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
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum CliAddressType {
    /// Legacy P2PKH (starts with 1)
    Legacy,
    /// SegWit P2SH-P2WPKH (starts with 3)
    Segwit,
    /// Native SegWit P2WPKH (starts with bc1q)
    NativeSegwit,
}

impl From<CliAddressType> for AddressType {
    fn from(val: CliAddressType) -> Self {
        match val {
            CliAddressType::Legacy => AddressType::P2pkh,
            CliAddressType::Segwit => AddressType::P2shP2wpkh,
            CliAddressType::NativeSegwit => AddressType::P2wpkh,
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
            } => {
                let network = if testnet {
                    Network::Testnet
                } else {
                    Network::Mainnet
                };
                let addr_type = AddressType::from(address_type);
                let wallet = Wallet::generate(words, passphrase.as_deref())?;
                let deriver = Deriver::new(&wallet, network)?;
                print_wallet(&wallet, &deriver, addr_type, count)?;
            }
            BitcoinSubcommand::Random {
                testnet,
                address_type,
            } => {
                let network = if testnet {
                    Network::Testnet
                } else {
                    Network::Mainnet
                };
                let addr_type = AddressType::from(address_type);
                let wallet = StandardWallet::generate(network, addr_type)?;
                print_standard_wallet(&wallet);
            }
            BitcoinSubcommand::Import {
                mnemonic,
                passphrase,
                testnet,
                address_type,
                count,
            } => {
                let network = if testnet {
                    Network::Testnet
                } else {
                    Network::Mainnet
                };
                let addr_type = AddressType::from(address_type);
                let wallet = Wallet::from_mnemonic(&mnemonic, passphrase.as_deref())?;
                let deriver = Deriver::new(&wallet, network)?;
                print_wallet(&wallet, &deriver, addr_type, count)?;
            }
        }
        Ok(())
    }
}

fn print_wallet(
    wallet: &Wallet,
    deriver: &Deriver,
    address_type: AddressType,
    count: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let network_str = match deriver.network() {
        Network::Mainnet => "Mainnet".green(),
        Network::Testnet => "Testnet".yellow(),
    };

    println!();
    println!("{}", "━".repeat(70).dimmed());
    println!("{}", " Bitcoin Wallet ".bold().on_blue());
    println!("{}", "━".repeat(70).dimmed());
    println!();
    println!(
        "{}: {}  |  {}: {}",
        "Network".bold(),
        network_str,
        "Address Type".bold(),
        address_type.name().cyan()
    );
    if wallet.has_passphrase() {
        println!("  {}", "(with passphrase)".dimmed());
    }
    println!();
    println!("{}", "Mnemonic:".bold());
    println!("  {}", wallet.mnemonic().yellow());
    println!();

    let addresses = deriver.derive_many(address_type, 0, false, 0, count)?;

    for (i, addr) in addresses.iter().enumerate() {
        println!("{} #{}", "Address".bold(), i);
        println!("  {}: {}", "Path".dimmed(), addr.path);
        println!("  {}: {}", "Address".dimmed(), addr.address.green());
        println!(
            "  {}: {}",
            "Private Key (WIF)".dimmed(),
            addr.private_key_wif.as_str().red()
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
    let network_str = match wallet.network() {
        Network::Mainnet => "Mainnet".green(),
        Network::Testnet => "Testnet".yellow(),
    };

    println!();
    println!("{}", "━".repeat(70).dimmed());
    println!("{}", " Bitcoin Standard Wallet ".bold().on_blue());
    println!("{}", "━".repeat(70).dimmed());
    println!();
    println!(
        "{}: {}  |  {}: {}",
        "Network".bold(),
        network_str,
        "Address Type".bold(),
        wallet.address_type().name().cyan()
    );
    println!();
    println!("{}", "Private Key (WIF):".bold());
    println!("  {}", wallet.private_key_wif().as_str().red());
    println!();
    println!("{}", "Public Key:".bold());
    println!("  {}", wallet.public_key_hex().dimmed());
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
