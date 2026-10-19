use std::fmt::Write as _;

use kobe::Chain;
use kobe::chains::bitcoin::{self, Bitcoin};
use kobe::chains::cosmos::Cosmos;
use kobe::chains::kaspa::{self, Kaspa};
use kobe::chains::litecoin::{self, Litecoin};
use kobe::chains::spark::Spark;

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
pub(crate) fn styles_help(header: &str, groups: &[(String, Box<dyn Chain>)]) -> String {
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
pub(crate) fn plain_styles_help(chain: impl Chain + 'static) -> String {
    styles_help(
        "Styles (-s <id|alias>, case-insensitive):",
        &[(String::new(), Box::new(chain))],
    )
}

pub(crate) fn bitcoin_styles_help() -> String {
    let groups: Vec<(String, Box<dyn Chain>)> = bitcoin::Kind::ALL
        .iter()
        .map(|kind| -> (String, Box<dyn Chain>) {
            (
                kind.to_string(),
                Box::new(Bitcoin::new(bitcoin::Network::Mainnet, *kind)),
            )
        })
        .collect();
    styles_help(
        "Styles per --type (mainnet templates; coin type is 1 on testnet/regtest):",
        &groups,
    )
}

pub(crate) fn litecoin_styles_help() -> String {
    let groups: Vec<(String, Box<dyn Chain>)> = litecoin::Kind::ALL
        .iter()
        .map(|kind| -> (String, Box<dyn Chain>) {
            (kind.to_string(), Box::new(Litecoin::new(*kind)))
        })
        .collect();
    styles_help("Styles per --type:", &groups)
}

pub(crate) fn kaspa_styles_help() -> String {
    let groups: Vec<(String, Box<dyn Chain>)> = kaspa::Encoding::ALL
        .iter()
        .map(|encoding| -> (String, Box<dyn Chain>) {
            (
                encoding.to_string(),
                Box::new(Kaspa::new(kaspa::Network::Mainnet, *encoding)),
            )
        })
        .collect();
    styles_help("Styles per --encoding:", &groups)
}

pub(crate) fn cosmos_styles_help() -> String {
    styles_help(
        "Styles (shown for --chain cosmos; the coin type follows --chain):",
        &[(String::new(), Box::new(Cosmos::default()))],
    )
}

pub(crate) fn spark_styles_help() -> String {
    styles_help(
        "Styles (the default index is 1 on mainnet, 0 on regtest):",
        &[(String::new(), Box::new(Spark::default()))],
    )
}
