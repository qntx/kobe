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
const SECRET_KEY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/secret-key.json"
));
const SECP256K1: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/secp256k1-ecdsa.json"
));
const BIP340: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/bip340.json"
));
const ED25519: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/ed25519.json"
));
const SLIP10: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/slip10.json"
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

/// `SecretKey::from_bytes` round-trip and length-error cases.
#[derive(Debug, Deserialize)]
struct SecretKeyCase {
    input: String,
    output: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SecretKeyVector {
    cases: Vec<SecretKeyCase>,
}

#[test]
fn secret_key() {
    let vector: SecretKeyVector =
        serde_json::from_str(SECRET_KEY).expect("secret-key.json must parse");
    assert!(!vector.cases.is_empty(), "secret-key.json has no cases");
    for (index, case) in vector.cases.iter().enumerate() {
        let bytes =
            hex::decode(&case.input).unwrap_or_else(|_| panic!("case {index}: input must be hex"));
        match (&case.output, &case.error) {
            (Some(output), None) => {
                let key = kobe_core::SecretKey::from_bytes(&bytes)
                    .unwrap_or_else(|e| panic!("case {index}: from_bytes failed: {e}"));
                assert_eq!(hex::encode(key.as_bytes()), output.as_str(), "case {index}");
            }
            (None, Some(error)) => {
                let err = kobe_core::SecretKey::from_bytes(&bytes)
                    .err()
                    .unwrap_or_else(|| panic!("case {index}: expected error {error}"));
                assert_eq!(
                    err.code().as_str(),
                    error.as_str(),
                    "case {index}: wrong error code"
                );
            }
            (output, error) => {
                panic!("case {index}: malformed (output {output:?}, error {error:?})")
            }
        }
    }
}

/// Mixed-shape secp256k1 case: sign/verify success, `valid: false` verify
/// rejection, or `error` (key load → input, scalar → crypto, digest → input).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Secp256k1Case {
    private_key: Option<String>,
    digest: Option<String>,
    compressed_public_key: Option<String>,
    uncompressed_public_key: Option<String>,
    signature: Option<String>,
    recovery: Option<u8>,
    signature_der: Option<String>,
    valid: Option<bool>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Secp256k1Vector {
    cases: Vec<Secp256k1Case>,
}

#[test]
fn secp256k1_ecdsa() {
    let vector: Secp256k1Vector =
        serde_json::from_str(SECP256K1).expect("secp256k1-ecdsa.json must parse");
    assert!(
        !vector.cases.is_empty(),
        "secp256k1-ecdsa.json has no cases"
    );
    for (index, case) in vector.cases.iter().enumerate() {
        let private_key = case
            .private_key
            .as_ref()
            .unwrap_or_else(|| panic!("case {index}: every case needs privateKey"));
        let key_bytes = hex::decode(private_key)
            .unwrap_or_else(|_| panic!("case {index}: privateKey must be hex"));
        let secret = kobe_core::SecretKey::from_bytes(&key_bytes);
        match &case.error {
            // Scalar out of range: key loads but signer construction fails.
            Some(error) if error == "crypto" => {
                let secret = secret.unwrap_or_else(|e| {
                    panic!("case {index}: key load must succeed before crypto error: {e}")
                });
                let err = kobe_core::Secp256k1Signer::new(&secret)
                    .err()
                    .unwrap_or_else(|| panic!("case {index}: expected crypto error"));
                assert_eq!(err.code().as_str(), "crypto", "case {index}");
            }
            // Input error: either the key itself or the digest length. The
            // Rust signer takes `&[u8; 32]`, so a non-32-byte digest is
            // unrepresentable at the type level — assert the fixture marks
            // it `input` and move on (TS exercises the thrown error).
            Some(error) => {
                if let Err(e) = &secret {
                    assert_eq!(e.code().as_str(), error.as_str(), "case {index}");
                } else {
                    let digest_hex = case
                        .digest
                        .as_ref()
                        .unwrap_or_else(|| panic!("case {index}: input error needs a field"));
                    assert_eq!(error.as_str(), "input", "case {index}");
                    assert_ne!(digest_hex.len() / 2, 32, "case {index}: bad digest length");
                }
            }
            None => {
                let secret =
                    secret.unwrap_or_else(|e| panic!("case {index}: from_bytes failed: {e}"));
                secp256k1_run_case(index, case, &secret);
            }
        }
    }
}

/// Run one success/verify-rejection secp256k1 case against a loaded secret.
fn secp256k1_run_case(index: usize, case: &Secp256k1Case, secret: &kobe_core::SecretKey) {
    let signer = kobe_core::Secp256k1Signer::new(secret)
        .unwrap_or_else(|e| panic!("case {index}: signer failed: {e}"));
    let digest_hex = case
        .digest
        .as_ref()
        .unwrap_or_else(|| panic!("case {index}: needs digest"));
    let digest: [u8; 32] = hex::decode(digest_hex)
        .unwrap_or_else(|_| panic!("case {index}: digest must be hex"))
        .try_into()
        .unwrap_or_else(|_| panic!("case {index}: digest must be 32 bytes"));
    let signature_hex = case
        .signature
        .as_ref()
        .unwrap_or_else(|| panic!("case {index}: needs signature"));
    let signature: [u8; 64] = hex::decode(signature_hex)
        .unwrap_or_else(|_| panic!("case {index}: signature must be hex"))
        .try_into()
        .unwrap_or_else(|_| panic!("case {index}: signature must be 64 bytes"));
    let recovery = case
        .recovery
        .unwrap_or_else(|| panic!("case {index}: needs recovery"));
    let mut recoverable = [0u8; 65];
    recoverable[..64].copy_from_slice(&signature);
    recoverable[64] = recovery;

    assert_eq!(
        hex::encode(signer.compressed_public_key()),
        case.compressed_public_key.as_deref().unwrap_or(""),
        "case {index}: compressedPublicKey"
    );
    assert_eq!(
        hex::encode(signer.uncompressed_public_key()),
        case.uncompressed_public_key.as_deref().unwrap_or(""),
        "case {index}: uncompressedPublicKey"
    );
    assert_eq!(
        signer.verify(&digest, &recoverable),
        case.valid.unwrap_or(true),
        "case {index}: verify"
    );
    if case.valid.unwrap_or(true) {
        let out = signer.sign_recoverable(&digest);
        assert_eq!(
            hex::encode(out.signature),
            signature_hex.as_str(),
            "case {index}"
        );
        assert_eq!(out.recovery, recovery, "case {index}: recovery");
        assert_eq!(out.to_bytes(), recoverable, "case {index}: to_bytes");
        assert_eq!(
            hex::encode(
                signer
                    .sign_der(&digest)
                    .unwrap_or_else(|e| panic!("case {index}: DER sign failed: {e}"))
            ),
            case.signature_der.as_deref().unwrap_or(""),
            "case {index}: signatureDer"
        );
    }
}

/// BIP-340 row: `secretKey` absent → verify-only (pubkey may be invalid).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Bip340Case {
    index: u32,
    secret_key: Option<String>,
    public_key: String,
    aux_rand: Option<String>,
    message: String,
    signature: String,
    valid: bool,
}

#[derive(Debug, Deserialize)]
struct Bip340Vector {
    cases: Vec<Bip340Case>,
}

#[test]
fn bip340() {
    let vector: Bip340Vector = serde_json::from_str(BIP340).expect("bip340.json must parse");
    assert!(!vector.cases.is_empty(), "bip340.json has no cases");
    for case in &vector.cases {
        let index = case.index;
        let public_key: [u8; 32] = hex::decode(&case.public_key)
            .unwrap_or_else(|_| panic!("vector {index}: publicKey must be hex"))
            .try_into()
            .unwrap_or_else(|_| panic!("vector {index}: publicKey must be 32 bytes"));
        let message = hex::decode(&case.message)
            .unwrap_or_else(|_| panic!("vector {index}: message must be hex"));
        let signature: [u8; 64] = hex::decode(&case.signature)
            .unwrap_or_else(|_| panic!("vector {index}: signature must be hex"))
            .try_into()
            .unwrap_or_else(|_| panic!("vector {index}: signature must be 64 bytes"));

        if let Some(secret_key) = &case.secret_key {
            let secret = kobe_core::SecretKey::from_bytes(
                &hex::decode(secret_key)
                    .unwrap_or_else(|_| panic!("vector {index}: secretKey must be hex")),
            )
            .unwrap_or_else(|e| panic!("vector {index}: from_bytes failed: {e}"));
            let signer = kobe_core::SchnorrSigner::new(&secret)
                .unwrap_or_else(|e| panic!("vector {index}: signer failed: {e}"));
            assert_eq!(
                hex::encode(signer.xonly_public_key()),
                case.public_key.as_str(),
                "vector {index}: xonlyPublicKey"
            );
            let aux_rand: [u8; 32] = hex::decode(
                case.aux_rand
                    .as_deref()
                    .unwrap_or_else(|| panic!("vector {index}: signing row needs auxRand")),
            )
            .unwrap_or_else(|_| panic!("vector {index}: auxRand must be hex"))
            .try_into()
            .unwrap_or_else(|_| panic!("vector {index}: auxRand must be 32 bytes"));
            let produced = signer
                .sign(&message, &aux_rand)
                .unwrap_or_else(|e| panic!("vector {index}: sign failed: {e}"));
            assert_eq!(
                hex::encode(produced),
                case.signature.as_str(),
                "vector {index}: signature"
            );
        }

        assert_eq!(
            kobe_core::SchnorrSigner::verify_with(&public_key, &message, &signature),
            case.valid,
            "vector {index}: verification result"
        );
    }
}

/// RFC 8032 case: `valid: false` marks a tampered-signature rejection.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ed25519Case {
    secret_key: String,
    public_key: String,
    message: String,
    signature: String,
    valid: bool,
}

#[derive(Debug, Deserialize)]
struct Ed25519Vector {
    cases: Vec<Ed25519Case>,
}

#[test]
fn ed25519() {
    let vector: Ed25519Vector = serde_json::from_str(ED25519).expect("ed25519.json must parse");
    assert!(!vector.cases.is_empty(), "ed25519.json has no cases");
    for (index, case) in vector.cases.iter().enumerate() {
        let secret = kobe_core::SecretKey::from_bytes(
            &hex::decode(&case.secret_key)
                .unwrap_or_else(|_| panic!("case {index}: secretKey must be hex")),
        )
        .unwrap_or_else(|e| panic!("case {index}: from_bytes failed: {e}"));
        let signer = kobe_core::Ed25519Signer::new(&secret);
        let message = hex::decode(&case.message)
            .unwrap_or_else(|_| panic!("case {index}: message must be hex"));
        let signature: [u8; 64] = hex::decode(&case.signature)
            .unwrap_or_else(|_| panic!("case {index}: signature must be hex"))
            .try_into()
            .unwrap_or_else(|_| panic!("case {index}: signature must be 64 bytes"));

        assert_eq!(
            hex::encode(signer.public_key()),
            case.public_key.as_str(),
            "case {index}: publicKey"
        );
        if case.valid {
            assert_eq!(
                hex::encode(signer.sign(&message)),
                case.signature.as_str(),
                "case {index}: signature"
            );
        }
        assert_eq!(
            signer.verify(&message, &signature),
            case.valid,
            "case {index}: verification result"
        );
    }
}

/// SLIP-10 Ed25519 chain: seed + hardened path → private key + 32-byte public key.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Slip10Case {
    seed: String,
    path: String,
    private_key: String,
    public_key: String,
}

#[derive(Debug, Deserialize)]
struct Slip10Vector {
    cases: Vec<Slip10Case>,
}

#[test]
fn slip10() {
    let vector: Slip10Vector = serde_json::from_str(SLIP10).expect("slip10.json must parse");
    assert!(!vector.cases.is_empty(), "slip10.json has no cases");
    for (index, case) in vector.cases.iter().enumerate() {
        let seed =
            hex::decode(&case.seed).unwrap_or_else(|_| panic!("case {index}: seed must be hex"));
        let key = kobe_core::slip10::DerivedEd25519Key::derive_path(&seed, &case.path)
            .unwrap_or_else(|e| panic!("case {index} ({}): derive failed: {e}", case.path));
        assert_eq!(
            key.private_key_hex().as_str(),
            case.private_key.as_str(),
            "case {index}: privateKey"
        );
        assert_eq!(
            hex::encode(key.public_key_bytes()),
            case.public_key.as_str(),
            "case {index}: publicKey"
        );
    }
}
