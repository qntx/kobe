#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    missing_docs,
    reason = "the CLI binary legitimately prints to stdout/stderr and its public items need no docs"
)]
//! kobe — pure offline HD wallet generator CLI.

use std::fmt::Write as _;
use std::process::ExitCode;
use std::str::FromStr;

use bip39::Language;
use clap::builder::{PossibleValuesParser, TypedValueParser};
use clap::{Parser, Subcommand};
use kobe::ada::{self, Cardano};
use kobe::aptos::Aptos;
use kobe::bch::BitcoinCash;
use kobe::btc::{self, Bitcoin};
use kobe::casper::Casper;
use kobe::cosmos::{self, Cosmos};
use kobe::doge::Dogecoin;
use kobe::evm::Evm;
use kobe::fil::{self, Filecoin};
use kobe::kaspa::{self, Kaspa};
use kobe::ltc::{self, Litecoin};
use kobe::near::Near;
use kobe::nostr::Nostr;
use kobe::sol::Solana;
use kobe::spark::{self, Spark};
use kobe::sui::Sui;
use kobe::ton::{self, Ton};
use kobe::tron::Tron;
use kobe::xlm::Stellar;
use kobe::xrp::Xrpl;
use kobe::{Account, Chain, ChildIndex, Style, Wallet, WordCount};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

/// `(id, chain, shared args, rendered options)` for one chain command.
struct ChainSpec<'a> {
    id: &'static str,
    chain: Box<dyn Chain>,
    args: &'a Args,
    options: Vec<(&'static str, Value)>,
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let json = argv.iter().any(|a| a == "--json");
    match Cli::try_parse_from(&argv) {
        Err(e) if e.use_stderr() => fail(&e.to_string(), json),
        Err(e) => {
            print!("{e}");
            ExitCode::SUCCESS
        }
        Ok(cli) => match run(&cli) {
            Ok(output) => {
                println!("{output}");
                ExitCode::SUCCESS
            }
            Err(e) => fail(&e.to_string(), json),
        },
    }
}

fn fail(message: &str, json: bool) -> ExitCode {
    if json {
        println!("{}", json!({ "error": message.trim() }));
    } else {
        eprintln!("error: {}", message.trim());
    }
    ExitCode::FAILURE
}

#[derive(Parser)]
#[command(
    name = "kobe",
    version,
    about = "Pure offline HD wallet generator (BIP-39 → keys → addresses)",
    propagate_version = true
)]
struct Cli {
    /// Emit JSON output
    #[arg(long, global = true)]
    json: bool,
    /// Show secrets (mnemonic, private keys)
    #[arg(short, long, global = true)]
    reveal: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a fresh BIP-39 mnemonic
    Mnemonic {
        /// Mnemonic word count: 12, 15, 18, 21 or 24
        #[arg(short, long, value_name = "N", default_value = "12")]
        words: WordCount,
    },
    /// Bitcoin (BIP-32, P2PKH/P2SH-P2WPKH/P2WPKH/P2TR)
    #[command(visible_alias = "bitcoin", after_help = btc_styles_help())]
    Btc {
        #[command(flatten)]
        args: Args,
        /// Address type
        #[arg(
            long = "type",
            value_name = "TYPE",
            default_value_t = btc::Kind::P2wpkh,
            value_parser = values(&btc::Kind::ALL)
        )]
        kind: btc::Kind,
        /// Target network
        #[arg(
            long,
            value_name = "NETWORK",
            default_value_t = btc::Network::Mainnet,
            value_parser = values(&btc::Network::ALL)
        )]
        network: btc::Network,
    },
    /// Litecoin (BIP-32 coin type 2)
    #[command(visible_alias = "litecoin", after_help = ltc_styles_help())]
    Ltc {
        #[command(flatten)]
        args: Args,
        /// Address type
        #[arg(
            long = "type",
            value_name = "TYPE",
            default_value_t = ltc::Kind::P2wpkh,
            value_parser = values(&ltc::Kind::ALL)
        )]
        kind: ltc::Kind,
    },
    /// Dogecoin (BIP-32 coin type 3, P2PKH)
    #[command(visible_alias = "dogecoin", after_help = plain_styles_help(Dogecoin))]
    Doge {
        #[command(flatten)]
        args: Args,
    },
    /// Bitcoin Cash (BIP-32 coin type 145, `CashAddr`)
    #[command(visible_alias = "bitcoincash", after_help = plain_styles_help(BitcoinCash))]
    Bch {
        #[command(flatten)]
        args: Args,
    },
    /// EVM chains (Ethereum & co, BIP-32 coin type 60)
    #[command(
        visible_aliases = ["eth", "ethereum"],
        after_help = plain_styles_help(Evm)
    )]
    Evm {
        #[command(flatten)]
        args: Args,
    },
    /// TRON (BIP-32 coin type 195)
    #[command(visible_alias = "trx", after_help = plain_styles_help(Tron))]
    Tron {
        #[command(flatten)]
        args: Args,
    },
    /// Cosmos SDK chains
    #[command(visible_alias = "atom", after_help = cosmos_styles_help())]
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
    #[command(visible_alias = "xrpl", after_help = plain_styles_help(Xrpl))]
    Xrp {
        #[command(flatten)]
        args: Args,
    },
    /// Filecoin (secp256k1, coin type 461)
    #[command(visible_alias = "filecoin", after_help = plain_styles_help(Filecoin::default()))]
    Fil {
        #[command(flatten)]
        args: Args,
        /// Target network
        #[arg(
            long,
            value_name = "NETWORK",
            default_value_t = fil::Network::Mainnet,
            value_parser = values(&fil::Network::ALL)
        )]
        network: fil::Network,
    },
    /// Kaspa (schnorr public-key addresses, coin type 111111)
    #[command(visible_alias = "kas", after_help = plain_styles_help(Kaspa::default()))]
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
    },
    /// Nostr (NIP-06)
    #[command(after_help = plain_styles_help(Nostr))]
    Nostr {
        #[command(flatten)]
        args: Args,
    },
    /// Spark (identity keys, bech32m)
    #[command(after_help = spark_styles_help())]
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
    #[command(visible_alias = "cspr", after_help = plain_styles_help(Casper))]
    Casper {
        #[command(flatten)]
        args: Args,
    },
    /// Solana (SLIP-10 ed25519, coin type 501)
    #[command(visible_aliases = ["solana", "svm"], after_help = plain_styles_help(Solana))]
    Sol {
        #[command(flatten)]
        args: Args,
    },
    /// Sui (SLIP-10 ed25519, coin type 784)
    #[command(after_help = plain_styles_help(Sui))]
    Sui {
        #[command(flatten)]
        args: Args,
    },
    /// Aptos (SLIP-10 ed25519, coin type 637)
    #[command(visible_alias = "apt", after_help = plain_styles_help(Aptos))]
    Aptos {
        #[command(flatten)]
        args: Args,
    },
    /// TON (SLIP-10 ed25519, coin type 607)
    #[command(after_help = plain_styles_help(Ton::default()))]
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
    #[command(visible_alias = "stellar", after_help = plain_styles_help(Stellar))]
    Xlm {
        #[command(flatten)]
        args: Args,
    },
    /// NEAR (SLIP-10 ed25519, coin type 397)
    #[command(after_help = plain_styles_help(Near))]
    Near {
        #[command(flatten)]
        args: Args,
    },
    /// Cardano (CIP-3 ed25519-bip32, Shelley addresses)
    #[command(visible_alias = "cardano", after_help = plain_styles_help(Cardano::default()))]
    Ada {
        #[command(flatten)]
        args: Args,
        /// Target network (`addr…` vs `addr_test…`)
        #[arg(
            long,
            value_name = "NETWORK",
            default_value_t = ada::Network::Mainnet,
            value_parser = values(&ada::Network::ALL)
        )]
        network: ada::Network,
        /// CIP-3 master-key algorithm (device family)
        #[arg(
            long,
            value_name = "MASTER",
            default_value_t = ada::Master::Icarus,
            value_parser = values(&ada::Master::ALL)
        )]
        master: ada::Master,
    },
}

/// Shared per-chain arguments.
#[derive(clap::Args)]
struct Args {
    /// Import a mnemonic ('-' reads one line from stdin)
    #[arg(short, long, value_name = "PHRASE", conflicts_with = "words")]
    mnemonic: Option<String>,
    /// Word count when generating (conflicts with -m)
    #[arg(short, long, value_name = "N", default_value = "12")]
    words: WordCount,
    /// BIP-39 passphrase
    #[arg(short, long, value_name = "PASSPHRASE", default_value = "")]
    passphrase: String,
    /// Derivation style id or alias (see below)
    #[arg(short, long, value_name = "STYLE", conflicts_with = "path")]
    style: Option<String>,
    /// Custom derivation path; use one {i} placeholder to iterate
    #[arg(long, value_name = "TEMPLATE")]
    path: Option<String>,
    /// First iterated index (default: style start)
    #[arg(short, long, value_name = "INDEX")]
    index: Option<u32>,
    /// Number of accounts (default 1)
    #[arg(short, long, value_name = "COUNT")]
    count: Option<u32>,
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

impl Command {
    /// `(id, chain, shared args, rendered options)`; `None` for non-chain commands.
    fn spec(&self) -> Option<ChainSpec<'_>> {
        macro_rules! spec {
            ($id:literal, $chain:expr, $args:expr) => {
                spec!($id, $chain, $args, Vec::new())
            };
            ($id:literal, $chain:expr, $args:expr, $options:expr) => {
                ChainSpec {
                    id: $id,
                    chain: Box::new($chain),
                    args: $args,
                    options: $options,
                }
            };
        }
        Some(match self {
            Self::Mnemonic { .. } => return None,
            Self::Btc {
                args,
                kind,
                network,
            } => spec!(
                "btc",
                Bitcoin::new(*network, *kind),
                args,
                vec![
                    ("type", json!(kind.to_string())),
                    ("network", json!(network.to_string())),
                ]
            ),
            Self::Ltc { args, kind } => spec!(
                "ltc",
                Litecoin::new(*kind),
                args,
                vec![("type", json!(kind.to_string()))]
            ),
            Self::Doge { args } => spec!("doge", Dogecoin, args),
            Self::Bch { args } => spec!("bch", BitcoinCash, args),
            Self::Evm { args } => spec!("evm", Evm, args),
            Self::Tron { args } => spec!("tron", Tron, args),
            Self::Cosmos { args, preset, hrp } => {
                let mut options = vec![("chain", json!(preset.to_string()))];
                if let Some(h) = hrp {
                    options.push(("hrp", json!(h)));
                }
                spec!(
                    "cosmos",
                    Cosmos {
                        preset: *preset,
                        hrp: hrp.clone(),
                    },
                    args,
                    options
                )
            }
            Self::Xrp { args } => spec!("xrp", Xrpl, args),
            Self::Fil { args, network } => spec!(
                "fil",
                Filecoin::new(*network),
                args,
                vec![("network", json!(network.to_string()))]
            ),
            Self::Kaspa { args, network } => spec!(
                "kaspa",
                Kaspa::new(*network),
                args,
                vec![("network", json!(network.to_string()))]
            ),
            Self::Nostr { args } => spec!("nostr", Nostr, args),
            Self::Spark { args, network } => spec!(
                "spark",
                Spark::new(*network),
                args,
                vec![("network", json!(network.to_string()))]
            ),
            Self::Casper { args } => spec!("casper", Casper, args),
            Self::Sol { args } => spec!("sol", Solana, args),
            Self::Sui { args } => spec!("sui", Sui, args),
            Self::Aptos { args } => spec!("aptos", Aptos, args),
            Self::Ton {
                args,
                contract,
                testnet,
                bounceable,
            } => spec!(
                "ton",
                Ton {
                    contract: *contract,
                    testnet: *testnet,
                    bounceable: *bounceable,
                },
                args,
                vec![
                    ("contract", json!(contract.to_string())),
                    ("testnet", json!(testnet)),
                    ("bounceable", json!(bounceable)),
                ]
            ),
            Self::Xlm { args } => spec!("xlm", Stellar, args),
            Self::Near { args } => spec!("near", Near, args),
            Self::Ada {
                args,
                network,
                master,
            } => spec!(
                "ada",
                Cardano::new(*network, *master),
                args,
                vec![
                    ("network", json!(network.to_string())),
                    ("master", json!(master.to_string())),
                ]
            ),
        })
    }
}

fn run(cli: &Cli) -> CliResult<String> {
    match &cli.command {
        Command::Mnemonic { words } => run_mnemonic(*words, cli.json),
        command => {
            let Some(spec) = command.spec() else {
                return Err("missing command".into());
            };
            run_chain(
                spec.id,
                spec.chain.as_ref(),
                spec.args,
                &spec.options,
                cli.json,
                cli.reveal,
            )
        }
    }
}

fn run_mnemonic(words: WordCount, json: bool) -> CliResult<String> {
    let wallet = Wallet::random(words, "")?;
    Ok(if json {
        json!({ "mnemonic": wallet.mnemonic(), "words": words.words() }).to_string()
    } else {
        wallet.mnemonic().to_owned()
    })
}

/// Read exactly one line of mnemonic from stdin.
fn read_stdin_line() -> CliResult<Zeroizing<String>> {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    if line.trim().is_empty() {
        return Err("no mnemonic on stdin".into());
    }
    Ok(Zeroizing::new(line.trim_end().to_owned()))
}

/// Expand a phrase where each token is either an exact BIP-39 English word
/// or a unique prefix of at least 4 letters.
fn expand_mnemonic(input: &str) -> CliResult<Zeroizing<String>> {
    let language = Language::English;
    let mut words: Vec<&'static str> = Vec::with_capacity(24);
    for raw in input.split_whitespace() {
        let token = Zeroizing::new(raw.to_lowercase());
        if let Some(index) = language.find_word(&token) {
            words.push(
                *language
                    .word_list()
                    .get(usize::from(index))
                    .ok_or("word index out of range")?,
            );
        } else if token.len() >= 4 {
            let mut iter = language
                .word_list()
                .iter()
                .filter(|w| w.starts_with(token.as_str()));
            if let (Some(w), None) = (iter.next(), iter.next()) {
                words.push(w);
            } else {
                return Err(format!("word {token:?} is not a unique BIP-39 prefix").into());
            }
        } else {
            return Err(format!("word {token:?} is not a BIP-39 English word").into());
        }
    }
    Ok(Zeroizing::new(words.join(" ")))
}

fn select_style(chain: &dyn Chain, sel: Option<&String>) -> CliResult<Style> {
    let styles = chain.styles();
    let Some(name) = sel else {
        return styles
            .into_iter()
            .next()
            .ok_or_else(|| "chain has no styles".into());
    };
    styles
        .iter()
        .find(|s| {
            s.id.eq_ignore_ascii_case(name)
                || s.aliases.iter().any(|a| a.eq_ignore_ascii_case(name))
        })
        .cloned()
        .ok_or_else(|| {
            let available = styles
                .iter()
                .map(|s| {
                    if s.aliases.is_empty() {
                        s.id.to_owned()
                    } else {
                        format!("{} ({})", s.id, s.aliases.join(", "))
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("unknown style {name:?} (available: {available})").into()
        })
}

fn run_chain(
    id: &str,
    chain: &dyn Chain,
    args: &Args,
    options: &[(&'static str, Value)],
    json: bool,
    reveal: bool,
) -> CliResult<String> {
    let passphrase = Zeroizing::new(args.passphrase.clone());
    let wallet = if let Some(source) = &args.mnemonic {
        let raw = if source == "-" {
            read_stdin_line()?
        } else {
            Zeroizing::new(source.clone())
        };
        let phrase = expand_mnemonic(&raw)?;
        Wallet::from_mnemonic(&phrase, &passphrase)?
    } else {
        Wallet::random(args.words, &passphrase)?
    };

    let style = match &args.path {
        Some(template) => Style::new("custom", template.clone(), ""),
        None => select_style(chain, args.style.as_ref())?,
    };

    let iterates = style.has_index();
    let start = args.index.unwrap_or(style.start);
    let count = if iterates { args.count.unwrap_or(1) } else { 1 };
    if count == 0 {
        return Err("count must be at least 1".into());
    }
    let last = u64::from(start) + u64::from(count) - 1;
    if last > u64::from(ChildIndex::MAX) {
        return Err(format!(
            "index range {start}..={last} exceeds the maximum {}",
            ChildIndex::MAX
        )
        .into());
    }

    let mut accounts = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
    for offset in 0..count {
        // Bounded by `last <= ChildIndex::MAX` above: cannot overflow.
        let index = start + offset;
        let path = style.path(index)?;
        accounts.push((index, chain.derive(&wallet, &path)?));
    }

    Ok(if json {
        json_output(id, options, &style, &wallet, &accounts, reveal)
    } else {
        human_output(id, options, &style, &wallet, &accounts, reveal)
    })
}

fn json_output(
    id: &str,
    options: &[(&'static str, Value)],
    style: &Style,
    wallet: &Wallet,
    accounts: &[(u32, Account)],
    reveal: bool,
) -> String {
    let mut root = Map::new();
    root.insert(String::from("chain"), json!(id));
    root.insert(
        String::from("options"),
        options
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect(),
    );
    root.insert(String::from("style"), json!(style.id));
    root.insert(String::from("template"), json!(style.template));
    if reveal {
        root.insert(String::from("mnemonic"), json!(wallet.mnemonic()));
    }
    root.insert(String::from("passphrase"), json!(wallet.has_passphrase()));

    let iterates = style.has_index();
    let mut list = Vec::with_capacity(accounts.len());
    for (index, account) in accounts {
        let mut item = Map::new();
        item.insert(
            String::from("index"),
            if iterates { json!(index) } else { Value::Null },
        );
        item.insert(String::from("path"), json!(account.path.to_string()));
        item.insert(String::from("address"), json!(account.address));
        item.insert(String::from("public_key"), json!(account.public_key));
        if reveal {
            item.insert(
                String::from("private_key"),
                json!(account.private_key.as_str()),
            );
        }
        for (key, value) in &account.extra {
            item.insert((*key).to_owned(), json!(value));
        }
        list.push(Value::Object(item));
    }
    root.insert(String::from("accounts"), Value::Array(list));
    Value::Object(root).to_string()
}

#[allow(
    clippy::let_underscore_must_use,
    reason = "writing to a String is infallible"
)]
fn human_output(
    id: &str,
    options: &[(&'static str, Value)],
    style: &Style,
    wallet: &Wallet,
    accounts: &[(u32, Account)],
    reveal: bool,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{:<10} {}", "chain", id);
    for (key, value) in options {
        let rendered = value
            .as_str()
            .map_or_else(|| value.to_string(), String::from);
        let _ = writeln!(out, "{key:<10} {rendered}");
    }
    let _ = writeln!(out, "{:<10} {}", "style", style.id);
    let _ = writeln!(out, "{:<10} {}", "template", style.template);
    let mnemonic = if reveal {
        wallet.mnemonic()
    } else {
        "<hidden>"
    };
    let _ = writeln!(out, "{:<10} {}", "mnemonic", mnemonic);
    let _ = writeln!(
        out,
        "{:<10} {}",
        "passphrase",
        if wallet.has_passphrase() {
            "set"
        } else {
            "none"
        }
    );
    out.push('\n');

    let iterates = style.has_index();
    for (index, account) in accounts {
        if iterates {
            let _ = writeln!(out, "#{index}  {}", account.path);
        } else {
            let _ = writeln!(out, "{}", account.path);
        }
        let mut rows = vec![
            ("address", account.address.as_str()),
            ("public_key", account.public_key.as_str()),
            (
                "private_key",
                if reveal {
                    account.private_key.as_str()
                } else {
                    "<hidden>"
                },
            ),
        ];
        for (key, value) in &account.extra {
            rows.push((*key, value.as_str()));
        }
        let width = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0) + 2;
        for (key, value) in rows {
            let _ = writeln!(out, "    {key:<width$} {value}");
        }
        out.push('\n');
    }

    if !reveal {
        out.push_str(
            "secrets hidden — rerun with --reveal to show the mnemonic and private keys\n",
        );
    }
    out.trim_end().to_owned()
}

#[allow(
    clippy::let_underscore_must_use,
    reason = "writing to a String is infallible"
)]
fn style_lines(out: &mut String, chain: &dyn Chain) {
    for style in chain.styles() {
        let aliases = if style.aliases.is_empty() {
            String::new()
        } else {
            format!(" (aliases: {})", style.aliases.join(", "))
        };
        let _ = writeln!(
            out,
            "  {:<14} {:<30} {}{}",
            style.id, style.template, style.wallets, aliases
        );
    }
}

/// One `--help` renderer: a header line plus `(label, chain)` style groups.
/// An empty label means the chain's styles render without a group heading.
#[allow(
    clippy::let_underscore_must_use,
    reason = "writing to a String is infallible"
)]
fn styles_help(header: &str, groups: &[(String, Box<dyn Chain>)]) -> String {
    let mut out = String::from(header);
    out.push('\n');
    for (label, chain) in groups {
        if !label.is_empty() {
            let _ = writeln!(out, "{label}:");
        }
        style_lines(&mut out, chain.as_ref());
    }
    out.push_str("\n--path accepts a custom template; use {i} for the iterated index.\n");
    out
}

/// `styles_help` for a single chain with no option-driven groups.
fn plain_styles_help(chain: impl Chain + 'static) -> String {
    styles_help(
        "Styles (-s <id|alias>, case-insensitive):",
        &[(String::new(), Box::new(chain))],
    )
}

fn btc_styles_help() -> String {
    let groups: Vec<(String, Box<dyn Chain>)> = btc::Kind::ALL
        .iter()
        .map(|kind| -> (String, Box<dyn Chain>) {
            (
                kind.to_string(),
                Box::new(Bitcoin::new(btc::Network::Mainnet, *kind)),
            )
        })
        .collect();
    styles_help(
        "Styles per --type (mainnet templates; coin type is 1 on testnet/regtest):",
        &groups,
    )
}

fn ltc_styles_help() -> String {
    let groups: Vec<(String, Box<dyn Chain>)> = ltc::Kind::ALL
        .iter()
        .map(|kind| -> (String, Box<dyn Chain>) {
            (kind.to_string(), Box::new(Litecoin::new(*kind)))
        })
        .collect();
    styles_help("Styles per --type:", &groups)
}

fn cosmos_styles_help() -> String {
    styles_help(
        "Styles (shown for --chain cosmos; the coin type follows --chain):",
        &[(String::new(), Box::new(Cosmos::default()))],
    )
}

fn spark_styles_help() -> String {
    styles_help(
        "Styles (the default index is 1 on mainnet, 0 on regtest):",
        &[(String::new(), Box::new(Spark::default()))],
    )
}
