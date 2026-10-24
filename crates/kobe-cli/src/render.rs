use std::fmt::Write as _;

use anstyle::{AnsiColor, Effects, Style};
use kobe::{Account, Style as HdStyle, Wallet};
use serde_json::{Map, Value, json};

const INDENT: &str = "      ";
const LABEL: Style = AnsiColor::Cyan.on_default().effects(Effects::BOLD);
const ADDRESS: Style = AnsiColor::Green.on_default();
const DIM: Style = Style::new().dimmed();
const WARN: Style = AnsiColor::Yellow.on_default();
const ERROR: Style = AnsiColor::Red.on_default().effects(Effects::BOLD);

pub(crate) const HIDDEN: &str = "(hidden; pass -r / --reveal)";

/// Map `Account.extra` keys to Title Case labels. Add new extras here —
/// the renderer never munges keys.
pub(crate) fn extra_label(key: &str) -> &'static str {
    match key {
        "stake_address" => "Stake Address",
        "account_hash" => "Account Hash",
        _ => "Extra",
    }
}

/// A display row: label (cyan bold), value styled plain/dim/green.
enum Val {
    Plain(String),
    Dim(String),
    Green(String),
}

fn emit(out: &mut String, width: usize, label: &str, val: &Val) {
    let _ignored = write!(
        out,
        "{INDENT}{}{}{label:<width$}",
        LABEL.render(),
        LABEL.render_reset()
    );
    match val {
        Val::Plain(v) => out.push_str(v),
        Val::Dim(v) => {
            let _dim = write!(out, "{}{}{}", DIM.render(), v, DIM.render_reset());
        }
        Val::Green(v) => {
            let _addr = write!(out, "{}{}{}", ADDRESS.render(), v, ADDRESS.render_reset());
        }
    }
    out.push('\n');
}

fn opt_label(key: &str) -> String {
    if key == "type" {
        return String::from("Address Type");
    }
    let mut out = String::with_capacity(key.len() + 1);
    for (i, part) in key.split('_').enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let mut chars = part.chars();
        if let Some(c) = chars.next() {
            out.push(c.to_ascii_uppercase());
        }
        out.push_str(chars.as_str());
    }
    out
}

/// v3-style labelled block output (ANSI escapes embedded; the caller
/// prints through `anstream` which strips them for non-TTY/NO_COLOR).
pub(crate) fn human_output(
    _id: &str,
    options: &[(&'static str, String, Value)],
    style: &HdStyle,
    wallet: &Wallet,
    accounts: &[(u32, Account)],
    reveal: bool,
    qr: bool,
) -> String {
    let mut header: Vec<(String, Val)> = Vec::new();
    for (key, label, _value) in options {
        header.push((opt_label(key), Val::Plain((*label).clone())));
    }
    header.push((
        String::from("Mnemonic"),
        if reveal {
            Val::Plain(wallet.mnemonic().to_owned())
        } else {
            Val::Dim(HIDDEN.to_owned())
        },
    ));
    if wallet.has_passphrase() {
        header.push((String::from("Passphrase"), Val::Dim(String::from("(set)"))));
    }
    let style_row = if style.id == "custom" {
        format!("custom {}", style.template)
    } else if style.wallets.is_empty() {
        style.id.to_owned()
    } else {
        format!("{} ({})", style.id, style.wallets)
    };
    header.push((
        String::from("Style"),
        if style.wallets.is_empty() {
            Val::Plain(style_row)
        } else {
            Val::Dim(style_row)
        },
    ));

    let multi = style.has_index() && accounts.len() > 1;
    let mut blocks: Vec<Vec<(String, Val)>> = Vec::new();
    for (index, account) in accounts {
        let mut rows: Vec<(String, Val)> = Vec::new();
        if multi {
            rows.push((String::from("Index"), Val::Dim(format!("[{index}]"))));
        }
        rows.push((String::from("Path"), Val::Plain(account.path.to_string())));
        rows.push((String::from("Address"), Val::Green(account.address.clone())));
        for (key, value) in &account.extra {
            rows.push((extra_label(key).to_owned(), Val::Green((*value).clone())));
        }
        rows.push((
            String::from("Private Key"),
            if reveal {
                Val::Plain(account.private_key.as_str().to_owned())
            } else {
                Val::Dim(HIDDEN.to_owned())
            },
        ));
        blocks.push(rows);
    }

    let width = header
        .iter()
        .chain(blocks.iter().flatten())
        .map(|(k, _)| k.len())
        .max()
        .unwrap_or(0)
        .max(12);

    let mut out = String::from('\n');
    for (k, v) in &header {
        emit(&mut out, width + 1, k, v);
    }
    for (i, block) in blocks.iter().enumerate() {
        out.push('\n');
        for (k, v) in block {
            emit(&mut out, width + 1, k, v);
        }
        if qr
            && let Some(text) = accounts
                .get(i)
                .and_then(|(_, a)| crate::qr::render(&a.address).ok())
        {
            out.push_str(&text);
        }
    }
    out.push('\n');
    out
}

pub(crate) fn json_output(
    id: &str,
    options: &[(&'static str, String, Value)],
    style: &HdStyle,
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
            .map(|(k, _l, v)| ((*k).to_owned(), v.clone()))
            .collect::<Map<String, Value>>()
            .into(),
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
    let v = Value::Object(root);
    serde_json::to_string_pretty(&v).unwrap_or_else(|_| v.to_string())
}

pub(crate) fn error_json(message: &str) -> String {
    let v = json!({ "error": message.trim() });
    serde_json::to_string_pretty(&v).unwrap_or_else(|_| v.to_string())
}

pub(crate) fn warn(message: &str) -> String {
    format!("{}{message}{}", WARN.render(), WARN.render_reset())
}

pub(crate) fn error_prefix() -> String {
    format!("{}Error:{}", ERROR.render(), ERROR.render_reset())
}

/// One `LABEL value` row inside a block (12-wide label column).
pub(crate) fn block_label(label: &str, value: &str) -> String {
    format!(
        "{INDENT}{}{}{label:<13}{}
",
        LABEL.render(),
        LABEL.render_reset(),
        value
    )
}

#[cfg(test)]
#[expect(
    clippy::literal_string_with_formatting_args,
    reason = "derivation templates use the {i} index placeholder"
)]
mod tests {
    use super::*;
    use kobe::Style;

    const M12: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn strip(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut iter = s.chars();
        while let Some(ch) = iter.next() {
            if ch == '\u{1b}' {
                let _skipped: String = iter.by_ref().take_while(|c| *c != 'm').collect();
            } else {
                out.push(ch);
            }
        }
        out
    }

    fn wallet() -> Wallet {
        Wallet::from_mnemonic(M12, "").expect("wallet")
    }

    fn bitcoin_accounts(count: u32) -> Vec<(u32, Account)> {
        use kobe::Chain;
        let chain = kobe::chains::bitcoin::Bitcoin::new(
            kobe::chains::bitcoin::Network::Mainnet,
            kobe::chains::bitcoin::Kind::P2wpkh,
        );
        (0..count)
            .map(|i| {
                let path = Style::new("standard", "m/84'/0'/0'/0/{i}", "wallets")
                    .path(i)
                    .expect("path");
                (i, chain.derive(&wallet(), &path).expect("derive"))
            })
            .collect()
    }

    #[test]
    fn snapshot_single_hidden() {
        let style = Style::new(
            "standard",
            "m/84'/0'/0'/0/{i}",
            "Sparrow, Electrum, BlueWallet, Trust Wallet",
        );
        let accounts = bitcoin_accounts(1);
        let options: Vec<(&'static str, String, Value)> = vec![
            ("network", "mainnet".to_owned(), json!("mainnet")),
            ("type", "P2WPKH (Native SegWit)".to_owned(), json!("p2wpkh")),
        ];
        let out = strip(&human_output(
            "bitcoin",
            &options,
            &style,
            &wallet(),
            &accounts,
            false,
            false,
        ));
        insta::assert_snapshot!(out);
    }

    #[test]
    fn snapshot_multi_revealed() {
        let style = Style::new(
            "standard",
            "m/84'/0'/0'/0/{i}",
            "Sparrow, Electrum, BlueWallet, Trust Wallet",
        );
        let accounts = bitcoin_accounts(2);
        let options: Vec<(&'static str, String, Value)> = vec![
            ("network", "mainnet".to_owned(), json!("mainnet")),
            ("type", "P2WPKH (Native SegWit)".to_owned(), json!("p2wpkh")),
        ];
        let out = strip(&human_output(
            "bitcoin",
            &options,
            &style,
            &wallet(),
            &accounts,
            true,
            false,
        ));
        insta::assert_snapshot!(out);
    }

    #[test]
    fn extra_labels() {
        assert_eq!(extra_label("stake_address"), "Stake Address");
        assert_eq!(extra_label("account_hash"), "Account Hash");
    }
}
