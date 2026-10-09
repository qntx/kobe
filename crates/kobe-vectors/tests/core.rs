//! Executes `vectors/core/*.json` and `vectors/bip39/trezor.json` against the
//! kobe-core public API.

#![allow(
    unused_crate_dependencies,
    reason = "integration tests do not import the lib crate's dependencies"
)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "a malformed fixture file must fail the test loudly"
)]
#![allow(
    clippy::tests_outside_test_module,
    reason = "integration test crate is itself the test module"
)]
#![allow(
    clippy::indexing_slicing,
    reason = "fixed-size Base58Check payloads are sliced at spec offsets"
)]

use kobe_core::Wallet;
use serde::Deserialize;

const TREZOR: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/bip39/trezor.json"
));
const BIP39: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/bip39.json"
));
const BIP32: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/bip32.json"
));
const BIP32_OFFICIAL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/bip32/official.json"
));
const MNEMONIC_EXPAND: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/mnemonic-expand.json"
));
const WALLET_ID: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/wallet-id.json"
));

/// `Option<&str>` passphrase for `Wallet` constructors: an empty vector
/// passphrase means "none supplied" (matches the TS `passphrase = ""`
/// default, where `hasPassphrase` is false).
fn passphrase(passphrase: Option<&String>) -> Option<&str> {
    passphrase.map(String::as_str).filter(|p| !p.is_empty())
}

/// The canonical Trezor BIP-39 file keeps its upstream shape:
/// `english: [[entropy, mnemonic, seed, xprv], …]` with passphrase
/// `"TREZOR"`. Only entropy → mnemonic and mnemonic → seed are exercised;
/// `xprv` is unused.
#[derive(Debug, Deserialize)]
struct TrezorVectors {
    english: Vec<[String; 4]>,
}

#[test]
fn bip39_trezor() {
    let vectors: TrezorVectors = serde_json::from_str(TREZOR).expect("trezor.json must parse");
    assert!(!vectors.english.is_empty(), "trezor.json has no cases");
    for (index, [entropy_hex, mnemonic, seed_hex, _xprv]) in vectors.english.iter().enumerate() {
        let entropy = hex::decode(entropy_hex)
            .unwrap_or_else(|_| panic!("case {index}: entropy must be hex"));
        let wallet = Wallet::from_entropy(&entropy, Some("TREZOR"))
            .unwrap_or_else(|e| panic!("case {index}: from_entropy failed: {e}"));
        assert_eq!(wallet.mnemonic(), mnemonic.as_str(), "case {index}");
        assert_eq!(
            hex::encode(wallet.seed().as_slice()),
            seed_hex.as_str(),
            "case {index}"
        );

        let rebuilt = Wallet::from_mnemonic(mnemonic, Some("TREZOR"))
            .unwrap_or_else(|e| panic!("case {index}: from_mnemonic failed: {e}"));
        assert_eq!(
            hex::encode(rebuilt.seed().as_slice()),
            seed_hex.as_str(),
            "case {index}"
        );
    }
}

/// Mixed-shape BIP-39 case: `input` + `mnemonic` = whitespace normalization;
/// `input` or `entropy` + `error` = expected failure code; otherwise a full
/// success case.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Bip39Case {
    input: Option<String>,
    mnemonic: Option<String>,
    passphrase: Option<String>,
    entropy: Option<String>,
    seed: Option<String>,
    word_count: Option<u32>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Bip39Vector {
    cases: Vec<Bip39Case>,
}

#[test]
fn bip39() {
    let vector: Bip39Vector = serde_json::from_str(BIP39).expect("bip39.json must parse");
    assert!(!vector.cases.is_empty(), "bip39.json has no cases");
    for (index, case) in vector.cases.iter().enumerate() {
        match (&case.input, &case.entropy, &case.mnemonic, &case.error) {
            // Expected failure from a phrase.
            (Some(input), None, _, Some(error)) => {
                let err = Wallet::from_mnemonic(input, None)
                    .err()
                    .unwrap_or_else(|| panic!("case {index}: expected error {error}"));
                assert_eq!(
                    err.code().as_str(),
                    error.as_str(),
                    "case {index}: wrong error code for {input:?}"
                );
            }
            // Expected failure from raw entropy.
            (None, Some(entropy_hex), _, Some(error)) => {
                let entropy = hex::decode(entropy_hex)
                    .unwrap_or_else(|_| panic!("case {index}: entropy must be hex"));
                let err = Wallet::from_entropy(&entropy, None)
                    .err()
                    .unwrap_or_else(|| panic!("case {index}: expected error {error}"));
                assert_eq!(
                    err.code().as_str(),
                    error.as_str(),
                    "case {index}: wrong error code for entropy {entropy_hex:?}"
                );
            }
            // Whitespace normalization.
            (Some(input), None, Some(expected), None) => {
                let wallet = Wallet::from_mnemonic(input, None)
                    .unwrap_or_else(|e| panic!("case {index}: from_mnemonic failed: {e}"));
                assert_eq!(wallet.mnemonic(), expected.as_str(), "case {index}");
            }
            // Full success case.
            (None, Some(entropy_hex), Some(mnemonic), None) => {
                let entropy = hex::decode(entropy_hex)
                    .unwrap_or_else(|_| panic!("case {index}: entropy must be hex"));
                let expected_seed = case
                    .seed
                    .as_ref()
                    .unwrap_or_else(|| panic!("case {index}: success case needs seed"));
                let word_count = case
                    .word_count
                    .unwrap_or_else(|| panic!("case {index}: success case needs wordCount"));

                let wallet = Wallet::from_entropy(&entropy, passphrase(case.passphrase.as_ref()))
                    .unwrap_or_else(|e| panic!("case {index}: from_entropy failed: {e}"));
                assert_eq!(wallet.mnemonic(), mnemonic.as_str(), "case {index}");
                assert_eq!(
                    hex::encode(wallet.seed().as_slice()),
                    expected_seed.as_str(),
                    "case {index}"
                );
                assert_eq!(wallet.word_count(), word_count as usize, "case {index}");

                let rebuilt = Wallet::from_mnemonic(mnemonic, passphrase(case.passphrase.as_ref()))
                    .unwrap_or_else(|e| panic!("case {index}: from_mnemonic failed: {e}"));
                assert_eq!(
                    hex::encode(rebuilt.seed().as_slice()),
                    expected_seed.as_str(),
                    "case {index}"
                );
            }
            (input, entropy, mnemonic, error) => panic!(
                "case {index}: malformed (input {input:?}, entropy {entropy:?}, mnemonic {mnemonic:?}, error {error:?})"
            ),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Bip32Case {
    mnemonic: String,
    passphrase: Option<String>,
    path: String,
    private_key: Option<String>,
    compressed_public_key: Option<String>,
    uncompressed_public_key: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Bip32Vector {
    cases: Vec<Bip32Case>,
}

#[test]
fn bip32() {
    let vector: Bip32Vector = serde_json::from_str(BIP32).expect("bip32.json must parse");
    assert!(!vector.cases.is_empty(), "bip32.json has no cases");
    for (index, case) in vector.cases.iter().enumerate() {
        let wallet = Wallet::from_mnemonic(&case.mnemonic, passphrase(case.passphrase.as_ref()))
            .unwrap_or_else(|e| panic!("case {index}: from_mnemonic failed: {e}"));
        match (&case.private_key, &case.error) {
            (None, Some(error)) => {
                let err = wallet
                    .derive_secp256k1(&case.path)
                    .err()
                    .unwrap_or_else(|| panic!("case {index}: expected error {error}"));
                assert_eq!(
                    err.code().as_str(),
                    error.as_str(),
                    "case {index}: wrong error code for path {:?}",
                    case.path
                );
            }
            (Some(private_key), None) => {
                let key = wallet
                    .derive_secp256k1(&case.path)
                    .unwrap_or_else(|e| panic!("case {index}: derive failed: {e}"));
                assert_eq!(
                    key.private_key_hex().as_str(),
                    private_key.as_str(),
                    "case {index}"
                );
                assert_eq!(
                    key.compressed_pubkey_hex(),
                    case.compressed_public_key
                        .as_ref()
                        .unwrap_or_else(|| panic!("case {index}: needs compressedPublicKey"))
                        .as_str(),
                    "case {index}"
                );
                assert_eq!(
                    key.uncompressed_pubkey_hex(),
                    case.uncompressed_public_key
                        .as_ref()
                        .unwrap_or_else(|| panic!("case {index}: needs uncompressedPublicKey"))
                        .as_str(),
                    "case {index}"
                );
            }
            (private_key, error) => {
                panic!("case {index}: malformed (privateKey {private_key:?}, error {error:?})")
            }
        }
    }
}

/// One link of an official BIP-32 test chain: path plus its `Base58Check`
/// extended keys. The checksum is not under test — only payload bytes are
/// compared (xprv key at 46..78, xpub compressed pubkey at 45..78).
#[derive(Debug, Deserialize)]
struct Bip32OfficialChain {
    path: String,
    xpub: String,
    xprv: String,
}

#[derive(Debug, Deserialize)]
struct Bip32OfficialCase {
    seed: String,
    chains: Vec<Bip32OfficialChain>,
}

#[derive(Debug, Deserialize)]
struct Bip32OfficialVector {
    cases: Vec<Bip32OfficialCase>,
}

#[test]
fn bip32_official() {
    let vector: Bip32OfficialVector =
        serde_json::from_str(BIP32_OFFICIAL).expect("official.json must parse");
    assert!(!vector.cases.is_empty(), "official.json has no cases");
    for (index, case) in vector.cases.iter().enumerate() {
        let seed =
            hex::decode(&case.seed).unwrap_or_else(|_| panic!("case {index}: seed must be hex"));
        for (chain_index, chain) in case.chains.iter().enumerate() {
            let label = format!("case {index} chain {chain_index} ({})", chain.path);
            let key = kobe_core::bip32::DerivedSecp256k1Key::derive(&seed, &chain.path)
                .unwrap_or_else(|e| panic!("{label}: derive failed: {e}"));
            let xprv = bs58::decode(&chain.xprv)
                .into_vec()
                .unwrap_or_else(|e| panic!("{label}: xprv must be base58: {e}"));
            let xpub = bs58::decode(&chain.xpub)
                .into_vec()
                .unwrap_or_else(|e| panic!("{label}: xpub must be base58: {e}"));
            assert_eq!(
                &key.private_key_bytes()[..],
                &xprv[46..78],
                "{label}: private key vs xprv payload"
            );
            assert_eq!(
                &key.compressed_pubkey()[..],
                &xpub[45..78],
                "{label}: compressed pubkey vs xpub payload"
            );
        }
    }
}

/// `Wallet::id` case: the BIP-32 master key (`m`) compressed public key and
/// the first 16 hex chars of `SHA-256("kobe/wallet-id/v1" ‖ pubkey)` are
/// both pinned so a divergence in the underlying BIP-32 stack cannot hide
/// inside the hash.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WalletIdCase {
    mnemonic: String,
    passphrase: Option<String>,
    master_public_key: String,
    id: String,
}

#[derive(Debug, Deserialize)]
struct WalletIdVector {
    cases: Vec<WalletIdCase>,
}

#[test]
fn wallet_id() {
    let vector: WalletIdVector =
        serde_json::from_str(WALLET_ID).expect("wallet-id.json must parse");
    assert!(!vector.cases.is_empty(), "wallet-id.json has no cases");
    for (index, case) in vector.cases.iter().enumerate() {
        let wallet = Wallet::from_mnemonic(&case.mnemonic, passphrase(case.passphrase.as_ref()))
            .unwrap_or_else(|e| panic!("case {index}: from_mnemonic failed: {e}"));
        let master = wallet
            .derive_secp256k1("m")
            .unwrap_or_else(|e| panic!("case {index}: master key derivation failed: {e}"));
        assert_eq!(
            master.compressed_pubkey_hex(),
            case.master_public_key.as_str(),
            "case {index}: master public key"
        );
        let id = wallet
            .id()
            .unwrap_or_else(|e| panic!("case {index}: id failed: {e}"));
        assert_eq!(id, case.id.as_str(), "case {index}: id");
    }
}

#[derive(Debug, Deserialize)]
struct MnemonicExpandCase {
    input: String,
    mnemonic: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MnemonicExpandVector {
    cases: Vec<MnemonicExpandCase>,
}

#[test]
fn mnemonic_expand() {
    let vector: MnemonicExpandVector =
        serde_json::from_str(MNEMONIC_EXPAND).expect("mnemonic-expand.json must parse");
    assert!(
        !vector.cases.is_empty(),
        "mnemonic-expand.json has no cases"
    );
    for (index, case) in vector.cases.iter().enumerate() {
        match (&case.mnemonic, &case.error) {
            (Some(expected), None) => {
                assert_eq!(
                    kobe_core::mnemonic::expand(&case.input)
                        .unwrap_or_else(|e| panic!("case {index}: expand failed: {e}")),
                    expected.as_str(),
                    "case {index}"
                );
            }
            (None, Some(error)) => {
                let err = kobe_core::mnemonic::expand(&case.input)
                    .err()
                    .unwrap_or_else(|| panic!("case {index}: expected error {error}"));
                assert_eq!(
                    err.code().as_str(),
                    error.as_str(),
                    "case {index}: wrong error code for {:?}",
                    case.input
                );
            }
            (mnemonic, error) => {
                panic!("case {index}: malformed (mnemonic {mnemonic:?}, error {error:?})")
            }
        }
    }
}
