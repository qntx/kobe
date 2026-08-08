//! Bitcoin wallet CLI commands.

use clap::{Args, Subcommand, ValueEnum};
use kobe::Wallet;
use kobe::btc::{AddressType, Deriver, Network};

use crate::commands::simple::SimpleArgs;
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
        #[command(flatten)]
        args: BitcoinArgs,
    },
    /// Import wallet from mnemonic phrase.
    Import {
        /// BIP39 mnemonic phrase.
        #[arg(short, long)]
        mnemonic: String,

        #[command(flatten)]
        args: BitcoinArgs,
    },
}

/// Bitcoin-specific CLI flags, on top of the shared mnemonic / count options.
#[derive(Args, Debug, Clone)]
struct BitcoinArgs {
    /// Use testnet instead of mainnet.
    #[arg(short, long)]
    testnet: bool,

    /// Address type to generate.
    #[arg(short, long, value_enum, default_value = "native-segwit")]
    address_type: CliAddressType,

    #[command(flatten)]
    common: SimpleArgs,
}

/// CLI-compatible address type enum.
#[derive(Clone, Copy, Debug, ValueEnum)]
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
        let (mnemonic, args) = match self.command {
            BitcoinSubcommand::New { args } => (None, args),
            BitcoinSubcommand::Import { mnemonic, args } => (Some(mnemonic), args),
        };
        let wallet = args.common.build_wallet(mnemonic.as_deref())?;

        let net = network(args.testnet);
        let addr_type = AddressType::from(args.address_type);
        let deriver = Deriver::new(&wallet, net);
        let addresses = deriver.derive_many_with(addr_type, 0, args.common.count)?;
        let out = build_hd(&wallet, net, addr_type, &addresses);
        output::render_hd_wallet(&out, json, args.common.qr)?;
        Ok(())
    }
}

fn build_hd(
    wallet: &Wallet,
    net: Network,
    addr_type: AddressType,
    addresses: &[kobe::btc::BtcAccount],
) -> HdWalletOutput {
    HdWalletOutput::new(
        "bitcoin",
        wallet,
        Some(net.name()),
        Some(addr_type.name()),
        None,
        addresses
            .iter()
            .enumerate()
            .map(|(i, a)| {
                AccountOutput::from_parts(i, a.path(), a.address(), a.private_key_wif().as_str())
            })
            .collect(),
    )
}
