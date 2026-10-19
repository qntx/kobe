use kobe::Chain;
use kobe::Style;
use kobe::chains::aptos::Aptos;
use kobe::chains::bitcoin::Bitcoin;
use kobe::chains::bitcoin_cash::BitcoinCash;
use kobe::chains::cardano::Cardano;
use kobe::chains::casper::Casper;
use kobe::chains::cosmos::Cosmos;
use kobe::chains::dogecoin::Dogecoin;
use kobe::chains::evm::Evm;
use kobe::chains::filecoin::Filecoin;
use kobe::chains::kaspa::Kaspa;
use kobe::chains::litecoin::Litecoin;
use kobe::chains::near::Near;
use kobe::chains::nostr::Nostr;
use kobe::chains::solana::Solana;
use kobe::chains::spark::Spark;
use kobe::chains::stellar::Stellar;
use kobe::chains::sui::Sui;
use kobe::chains::ton::Ton;
use kobe::chains::tron::Tron;
use kobe::chains::xrpl::Xrpl;
use serde_json::{Value, json};

use crate::cli::{Args, Command};

/// `(id, chain, shared args, rendered options)` for one chain command.
pub(crate) struct ChainSpec<'a> {
    pub(crate) id: &'static str,
    pub(crate) chain: Box<dyn Chain>,
    pub(crate) args: &'a Args,
    pub(crate) options: Vec<(&'static str, Value)>,
}

impl Command {
    /// `(id, chain, shared args, rendered options)`; `None` for non-chain commands.
    pub(crate) fn spec(&self) -> Option<ChainSpec<'_>> {
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
            Self::Bitcoin {
                args,
                kind,
                network,
            } => spec!(
                "bitcoin",
                Bitcoin::new(*network, *kind),
                args,
                vec![
                    ("type", json!(kind.to_string())),
                    ("network", json!(network.to_string())),
                ]
            ),
            Self::Litecoin { args, kind } => spec!(
                "litecoin",
                Litecoin::new(*kind),
                args,
                vec![("type", json!(kind.to_string()))]
            ),
            Self::Dogecoin { args } => spec!("dogecoin", Dogecoin, args),
            Self::BitcoinCash { args } => spec!("bitcoin-cash", BitcoinCash, args),
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
            Self::Xrpl { args } => spec!("xrpl", Xrpl, args),
            Self::Filecoin { args, network } => spec!(
                "filecoin",
                Filecoin::new(*network),
                args,
                vec![("network", json!(network.to_string()))]
            ),
            Self::Kaspa {
                args,
                network,
                encoding,
            } => spec!(
                "kaspa",
                Kaspa::new(*network, *encoding),
                args,
                vec![
                    ("network", json!(network.to_string())),
                    ("encoding", json!(encoding.to_string())),
                ]
            ),
            Self::Nostr { args } => spec!("nostr", Nostr, args),
            Self::Spark { args, network } => spec!(
                "spark",
                Spark::new(*network),
                args,
                vec![("network", json!(network.to_string()))]
            ),
            Self::Casper { args } => spec!("casper", Casper, args),
            Self::Solana { args } => spec!("solana", Solana, args),
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
            Self::Stellar { args } => spec!("stellar", Stellar, args),
            Self::Near { args } => spec!("near", Near, args),
            Self::Cardano {
                args,
                network,
                master,
            } => spec!(
                "cardano",
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

/// Resolve `-s/--style` to a style, or the default (first) style when `None`.
pub(crate) fn select_style(
    chain: &dyn Chain,
    sel: Option<&String>,
) -> Result<Style, Box<dyn std::error::Error>> {
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
