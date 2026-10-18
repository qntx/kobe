//! Byte-for-byte checks against official and reference vector files in
//! `vectors/`: BIP-39 (Trezor), BIP-84, BIP-86, plus generated btc/evm/sol
//! case files produced by `scripts/vectors`.
#![allow(
    unused_crate_dependencies,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "integration tests link feature deps indirectly and vector tests intentionally panic on malformed fixtures"
)]

use serde_json::Value;

#[cfg(feature = "ada")]
use kobe::ada::Cardano;
#[cfg(feature = "aptos")]
use kobe::aptos::Aptos;
#[cfg(feature = "bch")]
use kobe::bch::BitcoinCash;
#[cfg(feature = "btc")]
use kobe::btc::{Bitcoin, Kind, Network};
#[cfg(feature = "casper")]
use kobe::casper::Casper;
#[cfg(feature = "cosmos")]
use kobe::cosmos::Cosmos;
#[cfg(feature = "doge")]
use kobe::doge::Dogecoin;
#[cfg(feature = "evm")]
use kobe::evm::Evm;
#[cfg(feature = "fil")]
use kobe::fil::Filecoin;
#[cfg(feature = "kaspa")]
use kobe::kaspa::Kaspa;
#[cfg(feature = "ltc")]
use kobe::ltc::Litecoin;
#[cfg(feature = "near")]
use kobe::near::Near;
#[cfg(feature = "nostr")]
use kobe::nostr::Nostr;
#[cfg(feature = "sol")]
use kobe::sol::Solana;
#[cfg(feature = "spark")]
use kobe::spark::Spark;
#[cfg(feature = "sui")]
use kobe::sui::Sui;
#[cfg(feature = "ton")]
use kobe::ton::Ton;
#[cfg(feature = "tron")]
use kobe::tron::Tron;
#[cfg(feature = "xlm")]
use kobe::xlm::Stellar;
#[cfg(feature = "xrp")]
use kobe::xrp::Xrpl;
use kobe::{Chain, DerivationPath, Wallet};

fn load(name: &str) -> Value {
    let path = format!("{}/../../vectors/{name}.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[cfg_attr(
    not(feature = "all-chains"),
    allow(dead_code, reason = "shared by the feature-gated chain tests")
)]
fn assert_case(chain: &dyn Chain, wallet: &Wallet, case: &Value) {
    let path: DerivationPath = case["path"].as_str().unwrap().parse().unwrap();
    let account = chain.derive(wallet, &path).unwrap();
    assert_eq!(
        account.path.to_string(),
        case["path"].as_str().unwrap(),
        "path"
    );
    assert_eq!(
        account.address,
        case["address"].as_str().unwrap(),
        "address at {}",
        case["path"]
    );
    assert_eq!(
        account.public_key,
        case["public_key"].as_str().unwrap(),
        "public_key at {}",
        case["path"]
    );
    assert_eq!(
        account.private_key.as_str(),
        case["private_key"].as_str().unwrap(),
        "private_key at {}",
        case["path"]
    );
    assert_eq!(
        account.extra.len(),
        case.get("extra")
            .and_then(Value::as_object)
            .map_or(0, serde_json::Map::len),
        "extra field count at {}",
        case["path"]
    );
    for (key, value) in &account.extra {
        assert_eq!(
            case["extra"][key].as_str().unwrap(),
            value.as_str(),
            "extra.{key} at {}",
            case["path"]
        );
    }
}

#[cfg_attr(
    not(feature = "all-chains"),
    allow(dead_code, reason = "shared by the feature-gated chain tests")
)]
fn wallet(case: &Value) -> Wallet {
    Wallet::from_mnemonic(
        case["mnemonic"].as_str().unwrap(),
        case["passphrase"].as_str().unwrap(),
    )
    .unwrap()
}

/// Drive every case in a generated reference file, checking the covered
/// style set is exactly `expected_styles` in file order.
#[cfg_attr(
    not(feature = "all-chains"),
    allow(dead_code, reason = "shared by the feature-gated chain tests")
)]
fn reference_file(name: &str, chain: &dyn Fn(&Value) -> Box<dyn Chain>, expected_styles: &[&str]) {
    let file = load(name);
    let mut seen_styles = Vec::new();
    for case in file["cases"].as_array().unwrap() {
        let style = case["style"].as_str().unwrap();
        if !seen_styles.contains(&style) {
            seen_styles.push(style);
        }
        assert_case(chain(case).as_ref(), &wallet(case), case);
    }
    assert_eq!(seen_styles, expected_styles, "{name} style coverage");
}

/// BIP-39 Trezor vectors: entropy -> phrase and phrase round-trip.
#[test]
fn bip39_trezor() {
    let file = load("bip39");
    for case in file["cases"].as_array().unwrap() {
        let entropy = hex::decode(case["entropy"].as_str().unwrap()).unwrap();
        let phrase = case["phrase"].as_str().unwrap();
        let wallet = Wallet::from_entropy(&entropy, "").unwrap();
        assert_eq!(wallet.mnemonic(), phrase, "phrase from entropy");
        let imported = Wallet::from_mnemonic(phrase, "").unwrap();
        assert_eq!(imported.mnemonic(), phrase, "phrase round-trip");
    }
}

/// BIP-84 official vectors: P2WPKH addresses on mainnet.
#[cfg(feature = "btc")]
#[test]
fn bip84_p2wpkh() {
    let file = load("bip84");
    let w = Wallet::from_mnemonic(file["mnemonic"].as_str().unwrap(), "").unwrap();
    let chain = Bitcoin::new(Network::Mainnet, Kind::P2wpkh);
    for case in file["cases"].as_array().unwrap() {
        let path: DerivationPath = case["path"].as_str().unwrap().parse().unwrap();
        let account = chain.derive(&w, &path).unwrap();
        assert_eq!(
            account.address,
            case["address"].as_str().unwrap(),
            "bip84 address at {}",
            case["path"]
        );
    }
}

/// BIP-86 official vectors: internal key, tweaked output key, address.
#[cfg(feature = "btc")]
#[test]
fn bip86_p2tr() {
    let file = load("bip86");
    let w = Wallet::from_mnemonic(file["mnemonic"].as_str().unwrap(), "").unwrap();
    let chain = Bitcoin::new(Network::Mainnet, Kind::P2tr);
    for case in file["cases"].as_array().unwrap() {
        let path: DerivationPath = case["path"].as_str().unwrap().parse().unwrap();
        let account = chain.derive(&w, &path).unwrap();
        assert_eq!(
            account.address,
            case["address"].as_str().unwrap(),
            "bip86 address at {}",
            case["path"]
        );
        assert_eq!(
            &account.public_key[2..],
            case["internal_key"].as_str().unwrap(),
            "internal key at {}",
            case["path"]
        );
        let (_hrp, _version, program) = bech32::segwit::decode(&account.address).unwrap();
        assert_eq!(
            hex::encode(program),
            case["output_key"].as_str().unwrap(),
            "output key at {}",
            case["path"]
        );
    }
}

/// Generated reference vectors: all kinds, networks, styles, mnemonics.
#[cfg(feature = "btc")]
#[test]
fn btc_reference() {
    reference_file(
        "btc",
        &|case| {
            let options = &case["options"];
            Box::new(Bitcoin::new(
                options["network"].as_str().unwrap().parse().unwrap(),
                options["kind"].as_str().unwrap().parse().unwrap(),
            ))
        },
        &["standard", "account"],
    );
}

#[cfg(feature = "evm")]
#[test]
fn evm_reference() {
    reference_file(
        "evm",
        &|_| Box::new(Evm),
        &["standard", "ledger-live", "ledger-legacy"],
    );
}

#[cfg(feature = "sol")]
#[test]
fn sol_reference() {
    reference_file("sol", &|_| Box::new(Solana), &["bip44-change", "bip44"]);
}

/// NIP-06 official vectors (from vectors/nip06.json); same case shape as the
/// generated files so `assert_case` checks every field byte-for-byte.
#[cfg(feature = "nostr")]
#[test]
fn nip06_official() {
    let file = load("nip06");
    for case in file["cases"].as_array().unwrap() {
        assert_case(&Nostr, &wallet(case), case);
    }
}

/// SEP-0005 official vectors (from vectors/sep0005.json): strkey address and
/// secret seed. The file carries no raw `public_key` field.
#[cfg(feature = "xlm")]
#[test]
fn sep0005_official() {
    let file = load("sep0005");
    for case in file["cases"].as_array().unwrap() {
        let w = Wallet::from_mnemonic(
            case["mnemonic"].as_str().unwrap(),
            case["passphrase"].as_str().unwrap_or_default(),
        )
        .unwrap();
        let path: DerivationPath = case["path"].as_str().unwrap().parse().unwrap();
        let account = Stellar.derive(&w, &path).unwrap();
        assert_eq!(
            account.address,
            case["address"].as_str().unwrap(),
            "public address at {}",
            case["path"]
        );
        assert_eq!(
            account.private_key.as_str(),
            case["private_key"].as_str().unwrap(),
            "secret seed at {}",
            case["path"]
        );
    }
}

#[cfg(feature = "ltc")]
#[test]
fn ltc_reference() {
    reference_file(
        "ltc",
        &|case| {
            Box::new(Litecoin::new(
                case["options"]["kind"].as_str().unwrap().parse().unwrap(),
            ))
        },
        &["standard", "account"],
    );
}

#[cfg(feature = "doge")]
#[test]
fn doge_reference() {
    reference_file("doge", &|_| Box::new(Dogecoin), &["standard", "account"]);
}

#[cfg(feature = "bch")]
#[test]
fn bch_reference() {
    reference_file("bch", &|_| Box::new(BitcoinCash), &["standard", "account"]);
}

#[cfg(feature = "tron")]
#[test]
fn tron_reference() {
    reference_file("tron", &|_| Box::new(Tron), &["standard", "ledger-live"]);
}

#[cfg(feature = "cosmos")]
#[test]
fn cosmos_reference() {
    reference_file(
        "cosmos",
        &|case| {
            let options = &case["options"];
            let mut chain = Cosmos::new(options["chain"].as_str().unwrap().parse().unwrap());
            if let Some(hrp) = options["hrp"].as_str() {
                chain.hrp = Some(hrp.into());
            }
            Box::new(chain)
        },
        &["standard", "ledger-live"],
    );
}

#[cfg(feature = "xrp")]
#[test]
fn xrp_reference() {
    reference_file("xrp", &|_| Box::new(Xrpl), &["standard", "ledger-live"]);
}

#[cfg(feature = "fil")]
#[test]
fn fil_reference() {
    reference_file(
        "fil",
        &|case| {
            Box::new(Filecoin::new(
                case["options"]["network"]
                    .as_str()
                    .unwrap()
                    .parse()
                    .unwrap(),
            ))
        },
        &["standard"],
    );
}

#[cfg(feature = "kaspa")]
#[test]
fn kaspa_reference() {
    reference_file(
        "kaspa",
        &|case| {
            Box::new(Kaspa::new(
                case["options"]["network"]
                    .as_str()
                    .unwrap()
                    .parse()
                    .unwrap(),
            ))
        },
        &["standard"],
    );
}

#[cfg(feature = "nostr")]
#[test]
fn nostr_reference() {
    reference_file("nostr", &|_| Box::new(Nostr), &["nip06"]);
}

#[cfg(feature = "spark")]
#[test]
fn spark_reference() {
    reference_file(
        "spark",
        &|case| {
            Box::new(Spark::new(
                case["options"]["network"]
                    .as_str()
                    .unwrap()
                    .parse()
                    .unwrap(),
            ))
        },
        &["standard"],
    );
}

#[cfg(feature = "casper")]
#[test]
fn casper_reference() {
    reference_file("casper", &|_| Box::new(Casper), &["standard"]);
}

#[cfg(feature = "sui")]
#[test]
fn sui_reference() {
    reference_file("sui", &|_| Box::new(Sui), &["standard"]);
}

#[cfg(feature = "aptos")]
#[test]
fn aptos_reference() {
    reference_file("aptos", &|_| Box::new(Aptos), &["standard"]);
}

#[cfg(feature = "ton")]
#[test]
fn ton_reference() {
    reference_file(
        "ton",
        &|case| {
            let options = &case["options"];
            Box::new(Ton {
                testnet: options["testnet"].as_bool().unwrap(),
                bounceable: options["bounceable"].as_bool().unwrap(),
                ..Ton::new(options["contract"].as_str().unwrap().parse().unwrap())
            })
        },
        &["standard", "ledger-live"],
    );
}

#[cfg(feature = "xlm")]
#[test]
fn xlm_reference() {
    reference_file("xlm", &|_| Box::new(Stellar), &["sep5"]);
}

#[cfg(feature = "near")]
#[test]
fn near_reference() {
    reference_file("near", &|_| Box::new(Near), &["standard", "ledger-live"]);
}

#[cfg(feature = "ada")]
#[test]
fn ada_reference() {
    reference_file(
        "ada",
        &|case| {
            let options = &case["options"];
            Box::new(Cardano::new(
                options["network"].as_str().unwrap().parse().unwrap(),
                options["master"].as_str().unwrap().parse().unwrap(),
            ))
        },
        &["standard"],
    );
}
