use std::str::FromStr;

use clap::builder::{PossibleValuesParser, TypedValueParser};
use clap::{Parser, Subcommand};
use kobe::WordCount;
use kobe::chains::{
    bitcoin, bitcoin_cash, cardano, casper, cosmos, filecoin, kaspa, litecoin, spark, ton,
};

use crate::help;

#[derive(Parser)]
#[command(
    name = "kobe",
    version,
    about = "Pure offline HD wallet generator (BIP-39 → keys → addresses)",
    propagate_version = true
)]
pub(crate) struct Cli {
    /// Emit JSON output
    #[arg(long, global = true)]
    pub(crate) json: bool,
    /// Show secrets (mnemonic, private keys)
    #[arg(short, long, global = true)]
    pub(crate) reveal: bool,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Generate a fresh BIP-39 mnemonic (or run a subcommand)
    #[command(args_conflicts_with_subcommands = true)]
    Mnemonic {
        #[command(subcommand)]
        action: Option<MnemonicAction>,
        /// Mnemonic word count: 12, 15, 18, 21 or 24
        #[arg(short, long, value_name = "N", default_value = "12")]
        words: WordCount,
        /// Print the mnemonic as a `SeedQR` (requires `--reveal`)
        #[arg(long, value_name = "FORMAT", num_args = 0..=1,
              default_missing_value = "standard",
              value_parser = seedqr_kind)]
        seedqr: Option<String>,
    },
    /// Bitcoin (BIP-32, P2PKH/P2SH-P2WPKH/P2WPKH/P2TR)
    #[command(visible_alias = "btc", after_help = help::bitcoin_styles_help())]
    Bitcoin {
        #[command(flatten)]
        args: Args,
        /// Address type
        #[arg(
            long = "type",
            value_name = "TYPE",
            default_value_t = bitcoin::Kind::P2wpkh,
            value_parser = values(&bitcoin::Kind::ALL)
        )]
        kind: bitcoin::Kind,
        /// Target network
        #[arg(
            long,
            value_name = "NETWORK",
            default_value_t = bitcoin::Network::Mainnet,
            value_parser = values(&bitcoin::Network::ALL)
        )]
        network: bitcoin::Network,
    },
    /// Litecoin (BIP-32 coin type 2)
    #[command(visible_alias = "ltc", after_help = help::litecoin_styles_help())]
    Litecoin {
        #[command(flatten)]
        args: Args,
        /// Address type
        #[arg(
            long = "type",
            value_name = "TYPE",
            default_value_t = litecoin::Kind::P2wpkh,
            value_parser = values(&litecoin::Kind::ALL)
        )]
        kind: litecoin::Kind,
    },
    /// Dogecoin (BIP-32 coin type 3, P2PKH)
    #[command(visible_alias = "doge", after_help = help::plain_styles_help(kobe::chains::dogecoin::Dogecoin))]
    Dogecoin {
        #[command(flatten)]
        args: Args,
    },
    /// Bitcoin Cash (BIP-32 coin type 145, `CashAddr`)
    #[command(visible_alias = "bch", after_help = help::plain_styles_help(bitcoin_cash::BitcoinCash))]
    BitcoinCash {
        #[command(flatten)]
        args: Args,
    },
    /// EVM chains (Ethereum & co, BIP-32 coin type 60)
    #[command(
        visible_aliases = ["eth", "ethereum"],
        after_help = help::plain_styles_help(kobe::chains::evm::Evm)
    )]
    Evm {
        #[command(flatten)]
        args: Args,
    },
    /// TRON (BIP-32 coin type 195)
    #[command(visible_alias = "trx", after_help = help::plain_styles_help(kobe::chains::tron::Tron))]
    Tron {
        #[command(flatten)]
        args: Args,
    },
    /// Cosmos SDK chains
    #[command(visible_alias = "atom", after_help = help::cosmos_styles_help())]
    Cosmos {
        #[command(flatten)]
        args: Args,
        /// Chain preset (sets coin type and default bech32 prefix)
        #[arg(
            long = "chain",
            value_name = "CHAIN",
            default_value_t = cosmos::Preset::Cosmos,
            value_parser = values(&cosmos::Preset::ALL)
        )]
        preset: cosmos::Preset,
        /// Override the bech32 human-readable prefix
        #[arg(long, value_name = "HRP")]
        hrp: Option<String>,
    },
    /// XRP Ledger (secp256k1, coin type 144)
    #[command(visible_alias = "xrp", after_help = help::plain_styles_help(kobe::chains::xrpl::Xrpl))]
    Xrpl {
        #[command(flatten)]
        args: Args,
    },
    /// Filecoin (secp256k1, coin type 461)
    #[command(visible_alias = "fil", after_help = help::plain_styles_help(filecoin::Filecoin::default()))]
    Filecoin {
        #[command(flatten)]
        args: Args,
        /// Target network
        #[arg(
            long,
            value_name = "NETWORK",
            default_value_t = filecoin::Network::Mainnet,
            value_parser = values(&filecoin::Network::ALL)
        )]
        network: filecoin::Network,
    },
    /// Kaspa (schnorr public-key addresses, coin type 111111)
    #[command(visible_alias = "kas", after_help = help::kaspa_styles_help())]
    Kaspa {
        #[command(flatten)]
        args: Args,
        /// Target network
        #[arg(
            long,
            value_name = "NETWORK",
            default_value_t = kaspa::Network::Mainnet,
            value_parser = values(&kaspa::Network::ALL)
        )]
        network: kaspa::Network,
        /// Which public key the address carries
        #[arg(
            long,
            value_name = "ENCODING",
            default_value_t = kaspa::Encoding::Standard,
            value_parser = values(&kaspa::Encoding::ALL)
        )]
        encoding: kaspa::Encoding,
    },
    /// Nostr (NIP-06)
    #[command(after_help = help::plain_styles_help(kobe::chains::nostr::Nostr))]
    Nostr {
        #[command(flatten)]
        args: Args,
    },
    /// Spark (identity keys, bech32m)
    #[command(after_help = help::spark_styles_help())]
    Spark {
        #[command(flatten)]
        args: Args,
        /// Target network
        #[arg(
            long,
            value_name = "NETWORK",
            default_value_t = spark::Network::Mainnet,
            value_parser = values(&spark::Network::ALL)
        )]
        network: spark::Network,
    },
    /// Casper (secp256k1, coin type 506)
    #[command(visible_alias = "cspr", after_help = help::plain_styles_help(casper::Casper))]
    Casper {
        #[command(flatten)]
        args: Args,
    },
    /// Solana (SLIP-10 ed25519, coin type 501)
    #[command(visible_alias = "sol", after_help = help::plain_styles_help(kobe::chains::solana::Solana))]
    Solana {
        #[command(flatten)]
        args: Args,
    },
    /// Sui (SLIP-10 ed25519, coin type 784)
    #[command(after_help = help::plain_styles_help(kobe::chains::sui::Sui))]
    Sui {
        #[command(flatten)]
        args: Args,
    },
    /// Aptos (SLIP-10 ed25519, coin type 637)
    #[command(visible_alias = "apt", after_help = help::plain_styles_help(kobe::chains::aptos::Aptos))]
    Aptos {
        #[command(flatten)]
        args: Args,
    },
    /// TON (SLIP-10 ed25519, coin type 607)
    #[command(after_help = help::plain_styles_help(ton::Ton::default()))]
    Ton {
        #[command(flatten)]
        args: Args,
        /// Wallet contract version
        #[arg(
            long,
            value_name = "CONTRACT",
            default_value_t = ton::Contract::V4r2,
            value_parser = values(&ton::Contract::ALL)
        )]
        contract: ton::Contract,
        /// Emit testnet-only addresses (0Q…/kQ…)
        #[arg(long)]
        testnet: bool,
        /// Emit bounceable addresses (EQ…/kQ…)
        #[arg(long)]
        bounceable: bool,
    },
    /// Stellar (SEP-0005, coin type 148)
    #[command(visible_alias = "xlm", after_help = help::plain_styles_help(kobe::chains::stellar::Stellar))]
    Stellar {
        #[command(flatten)]
        args: Args,
    },
    /// NEAR (SLIP-10 ed25519, coin type 397)
    #[command(after_help = help::plain_styles_help(kobe::chains::near::Near))]
    Near {
        #[command(flatten)]
        args: Args,
    },
    /// Arweave (deterministic RSA-4096 or secp256k1)
    #[command(visible_alias = "ar")]
    Arweave {
        #[command(flatten)]
        args: Args,
    },
    /// Cardano (CIP-3 ed25519-bip32, Shelley addresses)
    #[command(visible_alias = "ada", after_help = help::plain_styles_help(cardano::Cardano::default()))]
    Cardano {
        #[command(flatten)]
        args: Args,
        /// Target network (`addr…` vs `addr_test…`)
        #[arg(
            long,
            value_name = "NETWORK",
            default_value_t = cardano::Network::Mainnet,
            value_parser = values(&cardano::Network::ALL)
        )]
        network: cardano::Network,
        /// CIP-3 master-key algorithm (device family)
        #[arg(
            long,
            value_name = "MASTER",
            default_value_t = cardano::Master::Icarus,
            value_parser = values(&cardano::Master::ALL)
        )]
        master: cardano::Master,
    },
}

/// Shared per-chain arguments.
#[derive(clap::Args)]
pub(crate) struct Args {
    /// Import a mnemonic ('-' reads one line from stdin)
    #[arg(short, long, value_name = "PHRASE", conflicts_with = "words")]
    pub(crate) mnemonic: Option<String>,
    /// Word count when generating (conflicts with -m)
    #[arg(short, long, value_name = "N", default_value = "12")]
    pub(crate) words: WordCount,
    /// BIP-39 passphrase ('-' prompts on the terminal without echo)
    #[arg(short, long, value_name = "PASSPHRASE", default_value = "")]
    pub(crate) passphrase: String,
    /// Derivation style id or alias (see below)
    #[arg(short, long, value_name = "STYLE", conflicts_with = "path")]
    pub(crate) style: Option<String>,
    /// Custom derivation path; use one {i} placeholder to iterate
    #[arg(long, value_name = "TEMPLATE")]
    pub(crate) path: Option<String>,
    /// First iterated index (default: style start)
    #[arg(short, long, value_name = "INDEX")]
    pub(crate) index: Option<u32>,
    /// Number of accounts (default 1)
    #[arg(short, long, value_name = "COUNT")]
    pub(crate) count: Option<u32>,
    /// Print a terminal QR for every derived address (ignored with --json)
    #[arg(long)]
    pub(crate) qr: bool,
}

/// Parse an option enum by its `FromStr` while listing `ALL` ids in `--help`.
fn values<T>(all: &'static [T]) -> impl TypedValueParser<Value = T>
where
    T: Copy + std::fmt::Display + FromStr + Send + Sync + 'static,
    T::Err: std::fmt::Display + Send + Sync + 'static,
{
    PossibleValuesParser::new(all.iter().map(ToString::to_string))
        .try_map(|s| T::from_str(&s).map_err(|e| e.to_string()))
}

/// `kobe mnemonic` subcommands.
#[derive(Subcommand)]
pub(crate) enum MnemonicAction {
    /// Camouflage a mnemonic behind a password
    Encrypt(CryptArgs),
    /// Recover the original mnemonic from a camouflaged one
    Decrypt(CryptArgs),
}

/// Shared arguments for `mnemonic encrypt|decrypt`.
#[derive(clap::Args)]
pub(crate) struct CryptArgs {
    /// Mnemonic to transform ('-' reads one line from stdin)
    #[arg(short, long, value_name = "PHRASE")]
    pub(crate) mnemonic: String,
    /// Read the password from stdin (one line; strips one trailing newline)
    #[arg(long)]
    pub(crate) password_stdin: bool,
    /// Allow a zxcvbn score below 3 (encrypt only)
    #[arg(long)]
    pub(crate) allow_weak_password: bool,
}

fn seedqr_kind(s: &str) -> Result<String, String> {
    match s {
        "standard" | "compact" => Ok(s.to_owned()),
        _ => Err("expected 'standard' or 'compact'".to_owned()),
    }
}
