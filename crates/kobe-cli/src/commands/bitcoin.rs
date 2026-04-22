//! Bitcoin wallet CLI commands.

use clap::{Args, Subcommand, ValueEnum};
use kobe::Wallet;
use kobe::btc::{AddressType, Deriver, Network};

use crate::output::{self, AccountOutput, HdWalletOutput};

/// Bitcoin wallet operations.
#[derive(Args)]
pub(crate) struct BitcoinCommand {
    #[command(subcommand)]
    /// The subcommand to execute.
    command: BitcoinSubcommand,
}

/// Bitcoin wallet subcommands.
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
}

/// CLI-compatible address type enum.
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

const fn network(testnet: bool) -> Network {
    if testnet {
        Network::Testnet
    } else {
        Network::Mainnet
    }
}

impl BitcoinCommand {
    pub(crate) fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            BitcoinSubcommand::New {
                testnet,
                words,
                passphrase,
                address_type,
                count,
                qr,
            } => {
                let net = network(testnet);
                let addr_type = AddressType::from(address_type);
                let wallet = Wallet::generate(words, passphrase.as_deref())?;
                let deriver = Deriver::new(&wallet, net)?;
                let addresses = deriver.derive_many_with(addr_type, 0, count)?;
                let out = build_hd(&wallet, net, addr_type, &addresses);
                output::render_hd_wallet(&out, json, qr)?;
            }
            BitcoinSubcommand::Import {
                mnemonic,
                passphrase,
                testnet,
                address_type,
                count,
                qr,
            } => {
                let net = network(testnet);
                let addr_type = AddressType::from(address_type);
                let expanded = kobe::mnemonic::expand(&mnemonic)?;
                let wallet = Wallet::from_mnemonic(&expanded, passphrase.as_deref())?;
                let deriver = Deriver::new(&wallet, net)?;
                let addresses = deriver.derive_many_with(addr_type, 0, count)?;
                let out = build_hd(&wallet, net, addr_type, &addresses);
                output::render_hd_wallet(&out, json, qr)?;
            }
        }
        Ok(())
    }
}

fn build_hd(
    wallet: &Wallet,
    net: Network,
    addr_type: AddressType,
    addresses: &[kobe::btc::DerivedAddress],
) -> HdWalletOutput {
    HdWalletOutput {
        chain: "bitcoin",
        network: Some(net.name()),
        address_type: Some(addr_type.name()),
        mnemonic: wallet.mnemonic().to_owned(),
        passphrase_protected: wallet.has_passphrase(),
        derivation_style: None,
        accounts: addresses
            .iter()
            .enumerate()
            .map(|(i, a)| AccountOutput {
                index: u32::try_from(i).unwrap_or(u32::MAX),
                derivation_path: a.path.to_string(),
                address: a.address.clone(),
                private_key: a.private_key_wif.to_string(),
            })
            .collect(),
    }
}
