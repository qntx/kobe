use std::fmt::Write as _;

use kobe::{Account, Style, Wallet};
use serde_json::{Map, Value, json};

pub(crate) fn json_output(
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
pub(crate) fn human_output(
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
