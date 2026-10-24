//! Byte-for-byte checks against official and reference vector files in
//! `vectors/`: BIP-39 (Trezor), BIP-39 passphrase rules, BIP-84, BIP-86,
//! plus generated chain case files produced by `scripts/vectors`.
#![allow(
    unused_crate_dependencies,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "integration tests link feature deps indirectly and vector tests intentionally panic on malformed fixtures"
)]

use serde_json::Value;

#[cfg(feature = "aptos")]
use kobe::chains::aptos::Aptos;
#[cfg(feature = "bitcoin")]
use kobe::chains::bitcoin::{Bitcoin, Kind, Network};
#[cfg(feature = "bitcoin-cash")]
use kobe::chains::bitcoin_cash::BitcoinCash;
#[cfg(feature = "cardano")]
use kobe::chains::cardano::Cardano;
#[cfg(feature = "casper")]
use kobe::chains::casper::Casper;
#[cfg(feature = "cosmos")]
use kobe::chains::cosmos::Cosmos;
#[cfg(feature = "dogecoin")]
use kobe::chains::dogecoin::Dogecoin;
#[cfg(feature = "evm")]
use kobe::chains::evm::Evm;
#[cfg(feature = "filecoin")]
use kobe::chains::filecoin::Filecoin;
#[cfg(feature = "kaspa")]
use kobe::chains::kaspa::Kaspa;
#[cfg(feature = "litecoin")]
use kobe::chains::litecoin::Litecoin;
#[cfg(feature = "near")]
use kobe::chains::near::Near;
#[cfg(feature = "nostr")]
use kobe::chains::nostr::Nostr;
#[cfg(feature = "solana")]
use kobe::chains::solana::Solana;
#[cfg(feature = "spark")]
use kobe::chains::spark::Spark;
#[cfg(feature = "stellar")]
use kobe::chains::stellar::Stellar;
#[cfg(feature = "sui")]
use kobe::chains::sui::Sui;
#[cfg(feature = "ton")]
use kobe::chains::ton::Ton;
#[cfg(feature = "tron")]
use kobe::chains::tron::Tron;
#[cfg(feature = "xrpl")]
use kobe::chains::xrpl::Xrpl;
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

/// BIP-39 passphrase rules (v4 vectors, verbatim): NFC and NFD forms of the
/// same passphrase produce the same seed, the empty passphrase equals none,
/// and passphrases are never trimmed. The seed itself is private, so each
/// case is observed through a fixed derived Solana address.
#[cfg(feature = "solana")]
#[test]
fn bip39_passphrase() {
    let file = load("bip39-passphrase");
    let cases = file["cases"].as_array().unwrap();
    let path: DerivationPath = "m/44'/501'/0'/0'".parse().unwrap();
    let derive = |case: &Value| -> (String, bool) {
        let w = Wallet::from_mnemonic(
            case["mnemonic"].as_str().unwrap(),
            case["passphrase"].as_str().unwrap(),
        )
        .unwrap();
        (
            Solana.derive(&w, &path).unwrap().address,
            w.has_passphrase(),
        )
    };

    let mut addresses = Vec::new();
    for case in cases {
        addresses.push(derive(case));
    }
    // The empty passphrase reports "none".
    assert!(!addresses.first().unwrap().1, "empty passphrase is none");
    // NFC "élève" and NFD "élève" derive the same address (cases 2 and 3).
    assert_eq!(
        addresses.get(2).unwrap().0,
        addresses.get(3).unwrap().0,
        "NFC vs NFD passphrase"
    );
    // "  spaced  " is not trimmed to "spaced" (cases 4 and 5).
    assert_ne!(
        addresses.get(4).unwrap().0,
        addresses.get(5).unwrap().0,
        "passphrase must not be trimmed"
    );
}

/// BIP-84 official vectors: P2WPKH addresses on mainnet.
#[cfg(feature = "bitcoin")]
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
#[cfg(feature = "bitcoin")]
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
#[cfg(feature = "bitcoin")]
#[test]
fn bitcoin_reference() {
    reference_file(
        "bitcoin",
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

#[cfg(feature = "solana")]
#[test]
fn solana_reference() {
    reference_file(
        "solana",
        &|_| Box::new(Solana),
        &["bip44-change", "bip44", "root"],
    );
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
#[cfg(feature = "stellar")]
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

#[cfg(feature = "litecoin")]
#[test]
fn litecoin_reference() {
    reference_file(
        "litecoin",
        &|case| {
            Box::new(Litecoin::new(
                case["options"]["kind"].as_str().unwrap().parse().unwrap(),
            ))
        },
        &["standard", "account"],
    );
}

#[cfg(feature = "dogecoin")]
#[test]
fn dogecoin_reference() {
    reference_file(
        "dogecoin",
        &|_| Box::new(Dogecoin),
        &["standard", "account"],
    );
}

#[cfg(feature = "bitcoin-cash")]
#[test]
fn bitcoin_cash_reference() {
    reference_file(
        "bitcoin-cash",
        &|_| Box::new(BitcoinCash),
        &["standard", "account"],
    );
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

#[cfg(feature = "xrpl")]
#[test]
fn xrpl_reference() {
    reference_file("xrpl", &|_| Box::new(Xrpl), &["standard", "ledger-live"]);
}

#[cfg(feature = "filecoin")]
#[test]
fn filecoin_reference() {
    reference_file(
        "filecoin",
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
            let options = &case["options"];
            Box::new(Kaspa::new(
                options["network"].as_str().unwrap().parse().unwrap(),
                options["encoding"]
                    .as_str()
                    .map(|s| s.parse().unwrap())
                    .unwrap_or_default(),
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

#[cfg(feature = "stellar")]
#[test]
fn stellar_reference() {
    reference_file("stellar", &|_| Box::new(Stellar), &["sep5"]);
}

#[cfg(feature = "near")]
#[test]
fn near_reference() {
    reference_file("near", &|_| Box::new(Near), &["standard", "ledger-live"]);
}

#[cfg(feature = "cardano")]
#[test]
fn cardano_reference() {
    reference_file(
        "cardano",
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

/// `option_enum!`'s `label()` contract: every variant has a
/// human-readable label, used by the CLI's text renderer.
#[cfg(feature = "all-chains")]
#[test]
fn option_labels() {
    use kobe::chains::bitcoin::{Kind as BtcKind, Network as BtcNetwork};
    use kobe::chains::cardano::Master;
    use kobe::chains::cosmos::Preset;
    use kobe::chains::kaspa::Encoding;
    use kobe::chains::ton::Contract;

    assert_eq!(BtcKind::P2wpkh.label(), "P2WPKH (Native SegWit)");
    assert_eq!(BtcKind::P2tr.label(), "P2TR (Taproot)");
    assert_eq!(BtcNetwork::Mainnet.label(), "mainnet");
    assert!(Master::Icarus.label().starts_with("icarus ("));
    assert_eq!(Contract::V4r2.label(), "v4r2");
    assert_eq!(Encoding::Onekey.label(), "OneKey");
    assert_eq!(Preset::Osmosis.label(), "Osmosis");
}

/// `SeedQR` payloads against the nine official `SeedSigner` vectors in
/// `vectors/seedqr.json` (words → standard digit stream / compact entropy).
#[allow(clippy::expect_used, reason = "vector files must parse in tests")]
#[cfg(all(feature = "all-chains", test))]
mod seedqr_vectors {
    use kobe::Wallet;
    fn vectors() -> serde_json::Value {
        serde_json::from_str::<serde_json::Value>(include_str!("../../../vectors/seedqr.json"))
            .expect("seedqr vectors json")
    }

    #[test]
    fn standard_and_compact_match_spec() {
        let file = vectors();
        let list = file["vectors"].as_array().expect("vectors array");
        assert_eq!(list.len(), 9, "all nine spec vectors present");
        for v in list {
            let phrase = v["phrase"].as_str().expect("phrase");
            let wallet = Wallet::from_mnemonic(phrase, "").expect("wallet");
            let standard = kobe::seedqr::standard(&wallet).expect("standard");
            let digits: String = v["standard"].as_str().expect("digits").replace(' ', "");
            assert_eq!(standard.as_str(), digits, "standard digits for {phrase:?}");
            let compact = kobe::seedqr::compact(&wallet).expect("compact");
            let want = v["compact"].as_str().expect("entropy");
            let got: String = compact.iter().fold(String::new(), |mut s, b| {
                use std::fmt::Write as _;
                write!(s, "{b:02x}").expect("write");
                s
            });
            assert_eq!(got, want, "compact entropy for {phrase:?}");
        }
    }

    #[test]
    fn rejects_unsupported_word_counts() {
        // 15-word mnemonic (160-bit entropy, valid BIP-39) must error.
        let entropy = [7u8; 20];
        let w15 = Wallet::from_entropy(&entropy, "").expect("15-word wallet");
        assert!(kobe::seedqr::standard(&w15).is_err());
        assert!(kobe::seedqr::compact(&w15).is_err());
    }
}

/// `kobe::camouflage` against `vectors/camouflage.json` — generated from
/// the kobe v4.0.0 release binary and the independent TS implementation in
/// `scripts/vectors/camouflage-generate.ts` (byte-identical).
#[allow(clippy::expect_used, reason = "vector files must parse in tests")]
#[cfg(feature = "camouflage")]
mod camouflage_vectors {
    use kobe::Wallet;

    fn vectors() -> serde_json::Value {
        serde_json::from_str::<serde_json::Value>(include_str!("../../../vectors/camouflage.json"))
            .expect("camouflage vectors json")
    }

    #[test]
    fn encrypt_decrypt_match_spec() {
        let file = vectors();
        let list = file["vectors"].as_array().expect("vectors");
        assert_eq!(list.len(), 21);
        for v in list {
            let phrase = v["phrase"].as_str().expect("phrase");
            let password = v["password"].as_str().expect("password");
            let want = v["camouflaged"].as_str().expect("camouflaged");
            let decrypt_only = v["decrypt_only"].as_bool().unwrap_or(false);

            if decrypt_only {
                // NFD password: decrypt accepts raw bytes.
                let cam = Wallet::from_mnemonic(want, "").expect("cam wallet");
                let back = kobe::camouflage::decrypt(&cam, password).expect("decrypt");
                assert_eq!(back.as_str(), phrase, "NFD decrypt for {phrase:?}");
                continue;
            }

            let wallet = Wallet::from_mnemonic(phrase, "").expect("wallet");
            let cam = kobe::camouflage::encrypt(&wallet, password).expect("encrypt");
            assert_eq!(cam.as_str(), want, "encrypt for {phrase:?}");

            // round-trip
            let cam_w = Wallet::from_mnemonic(&cam, "").expect("cam wallet");
            let back = kobe::camouflage::decrypt(&cam_w, password).expect("decrypt");
            assert_eq!(back.as_str(), phrase, "decrypt for {phrase:?}");

            // fingerprint matches the vector
            let fp = wallet.fingerprint().expect("fingerprint");
            let fp_hex: String = fp.iter().fold(String::new(), |mut s, b| {
                use std::fmt::Write as _;
                write!(s, "{b:02x}").expect("w");
                s
            });
            assert_eq!(fp_hex, v["fingerprint"].as_str().expect("fp"));
        }
    }

    #[test]
    fn wrong_password_yields_different_valid_mnemonic() {
        let phrase = "chuckle fiscal front time change dutch floor ramp warrior autumn prefer much";
        let wallet = Wallet::from_mnemonic(phrase, "").expect("wallet");
        let cam =
            kobe::camouflage::encrypt(&wallet, "correct horse battery staple").expect("encrypt");
        let cam_w = Wallet::from_mnemonic(&cam, "").expect("cam wallet");
        let other = kobe::camouflage::decrypt(&cam_w, "wrong password").expect("decrypt");
        assert_ne!(other.as_str(), phrase);
        // `other` is still a valid mnemonic — Wallet::from_mnemonic accepted it above via cam_w.
        assert!(Wallet::from_mnemonic(&other, "").is_ok());
    }

    #[test]
    fn empty_password_rejected() {
        let wallet = Wallet::from_mnemonic(
            "chuckle fiscal front time change dutch floor ramp warrior autumn prefer much",
            "",
        )
        .expect("wallet");
        assert!(kobe::camouflage::encrypt(&wallet, "").is_err());
        assert!(kobe::camouflage::decrypt(&wallet, "").is_err());
    }

    #[test]
    fn nfd_password_rejected_by_encrypt_accepted_by_decrypt() {
        let nfd = "pa\u{0308}sswo\u{0308}rd";
        let wallet = Wallet::from_mnemonic(
            "chuckle fiscal front time change dutch floor ramp warrior autumn prefer much",
            "",
        )
        .expect("wallet");
        assert!(!kobe::camouflage::is_nfc(nfd));
        assert!(kobe::camouflage::is_nfc("pässwörd"));
        assert!(kobe::camouflage::encrypt(&wallet, nfd).is_err());
        assert!(kobe::camouflage::decrypt(&wallet, nfd).is_ok());
    }

    #[test]
    fn fingerprint_bip32_reference() {
        // abandon×11 + about, empty passphrase → 73c5da0a (BIP-32 spec).
        let wallet = Wallet::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
        )
        .expect("wallet");
        let fp = wallet.fingerprint().expect("fp");
        assert_eq!(
            fp.iter().fold(String::new(), |mut s, b| {
                use std::fmt::Write as _;
                write!(s, "{b:02x}").expect("w");
                s
            }),
            "73c5da0a"
        );
    }
}

#[cfg(feature = "arweave")]
mod arweave_vectors {
    use kobe::Chain;
    use kobe::chains::arweave::Arweave;
    use kobe::{DerivationPath, Wallet};

    fn wallet(phrase: &str, passphrase: &str) -> Wallet {
        Wallet::from_mnemonic(phrase, passphrase).unwrap()
    }

    #[test]
    fn rsa_vectors() {
        let raw = include_str!("../../../vectors/arweave.json");
        let doc: serde_json::Value = serde_json::from_str(raw).unwrap();
        for v in doc["rsa"].as_array().unwrap() {
            let w = wallet(
                v["mnemonic"].as_str().unwrap(),
                v["passphrase"].as_str().unwrap(),
            );
            let chain = Arweave::new(false);
            let account = chain
                .derive(&w, &"m".parse::<DerivationPath>().unwrap())
                .unwrap();
            assert_eq!(
                account.address,
                v["address"].as_str().unwrap(),
                "{}",
                v["id"]
            );
            let jwk = &v["jwk"];
            let expect = format!(
                "{{\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"{}\",\"d\":\"{}\",\"p\":\"{}\",\"q\":\"{}\",\"dp\":\"{}\",\"dq\":\"{}\",\"qi\":\"{}\"}}",
                jwk["n"].as_str().unwrap(),
                jwk["d"].as_str().unwrap(),
                jwk["p"].as_str().unwrap(),
                jwk["q"].as_str().unwrap(),
                jwk["dp"].as_str().unwrap(),
                jwk["dq"].as_str().unwrap(),
                jwk["qi"].as_str().unwrap()
            );
            assert_eq!(account.private_key.as_str(), expect, "{}", v["id"]);
            assert_eq!(
                account.public_key,
                jwk["n"].as_str().unwrap(),
                "{}",
                v["id"]
            );
        }
    }

    #[test]
    fn ecdsa_vectors() {
        let raw = include_str!("../../../vectors/arweave.json");
        let doc: serde_json::Value = serde_json::from_str(raw).unwrap();
        let mut phrases = std::collections::HashMap::new();
        phrases.insert("abandon12", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        phrases.insert("m24", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art");
        for v in doc["ecdsa"].as_array().unwrap() {
            let w = wallet(phrases[v["mnemonic"].as_str().unwrap()], "");
            let path: DerivationPath = v["path"].as_str().unwrap().parse().unwrap();
            let account = Arweave::new(true).derive(&w, &path).unwrap();
            assert_eq!(account.address, v["address"].as_str().unwrap());
            assert_eq!(account.public_key, v["public_key"].as_str().unwrap());
            assert_eq!(
                account.private_key.as_str(),
                v["private_key"].as_str().unwrap()
            );
        }
    }
}
