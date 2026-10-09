//! Executes `vectors/vault/*.json` against the kobe-vault public API.

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
    reason = "vector byte offsets are fixed by the envelope layout"
)]

use kobe_nostr::Deriver;
use serde::Deserialize;

const SEAL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/vault/seal.json"
));
const PASSWORD_KEY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/vault/password-key.json"
));
const PRF_KEY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/vault/prf-key.json"
));
const PASSKEY_WALLET: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/vault/passkey-wallet.json"
));

/// Deterministic RNG that emits the vector nonce, then zeros.
struct FixedRng {
    nonce: Vec<u8>,
}

impl rand_core::TryRng for FixedRng {
    type Error = rand_core::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(0)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(0)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        dst.copy_from_slice(&self.nonce[..dst.len()]);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for FixedRng {}

/// `nonce` present → success case; `error` present → expected failure code.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SealCase {
    key: String,
    context: String,
    nonce: Option<String>,
    plaintext: Option<String>,
    sealed: String,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SealVector {
    cases: Vec<SealCase>,
}

#[test]
fn seal() {
    let vector: SealVector = serde_json::from_str(SEAL).expect("seal.json must parse");
    assert!(!vector.cases.is_empty(), "seal.json has no cases");
    for (index, case) in vector.cases.iter().enumerate() {
        let key =
            hex::decode(&case.key).unwrap_or_else(|_| panic!("case {index}: key must be hex"));
        let sealed = hex::decode(&case.sealed)
            .unwrap_or_else(|_| panic!("case {index}: sealed must be hex"));
        match (&case.nonce, &case.plaintext, &case.error) {
            (Some(nonce_hex), Some(plaintext_hex), None) => {
                let nonce = hex::decode(nonce_hex)
                    .unwrap_or_else(|_| panic!("case {index}: nonce must be hex"));
                let plaintext = hex::decode(plaintext_hex)
                    .unwrap_or_else(|_| panic!("case {index}: plaintext must be hex"));
                let mut rng = FixedRng { nonce };
                let out = kobe_vault::seal(&key, &plaintext, &case.context, &mut rng)
                    .unwrap_or_else(|e| panic!("case {index}: seal failed: {e}"));
                assert_eq!(hex::encode(&out), case.sealed.as_str(), "case {index}");
                let opened = kobe_vault::open(&key, &sealed, &case.context)
                    .unwrap_or_else(|e| panic!("case {index}: open failed: {e}"));
                assert_eq!(
                    hex::encode(opened.as_slice()),
                    plaintext_hex.as_str(),
                    "case {index}"
                );
            }
            (None, None, Some(error)) => {
                let err = kobe_vault::open(&key, &sealed, &case.context)
                    .err()
                    .unwrap_or_else(|| panic!("case {index}: expected error {error}"));
                assert_eq!(err.code().as_str(), error.as_str(), "case {index}");
            }
            _ => panic!("case {index}: malformed seal case"),
        }
    }
}

/// `key` present → success case; `error` present → expected failure code.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordKeyCase {
    password: String,
    salt: String,
    iterations: u32,
    key: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PasswordKeyVector {
    cases: Vec<PasswordKeyCase>,
}

#[test]
fn password_key() {
    let vector: PasswordKeyVector =
        serde_json::from_str(PASSWORD_KEY).expect("password-key.json must parse");
    assert!(!vector.cases.is_empty(), "password-key.json has no cases");
    for (index, case) in vector.cases.iter().enumerate() {
        let salt =
            hex::decode(&case.salt).unwrap_or_else(|_| panic!("case {index}: salt must be hex"));
        match (&case.key, &case.error) {
            (Some(key_hex), None) => {
                let key = kobe_vault::password_key(&case.password, &salt, case.iterations)
                    .unwrap_or_else(|e| panic!("case {index}: password_key failed: {e}"));
                assert_eq!(hex::encode(*key), key_hex.as_str(), "case {index}");
            }
            (None, Some(error)) => {
                let err = kobe_vault::password_key(&case.password, &salt, case.iterations)
                    .err()
                    .unwrap_or_else(|| panic!("case {index}: expected error {error}"));
                assert_eq!(err.code().as_str(), error.as_str(), "case {index}");
            }
            _ => panic!("case {index}: malformed password-key case"),
        }
    }
}

/// `key` present → success case; `error` present → expected failure code.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PrfKeyCase {
    prf: String,
    info: String,
    key: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PrfKeyVector {
    cases: Vec<PrfKeyCase>,
}

#[test]
fn prf_key() {
    let vector: PrfKeyVector = serde_json::from_str(PRF_KEY).expect("prf-key.json must parse");
    assert!(!vector.cases.is_empty(), "prf-key.json has no cases");
    for (index, case) in vector.cases.iter().enumerate() {
        let prf =
            hex::decode(&case.prf).unwrap_or_else(|_| panic!("case {index}: prf must be hex"));
        match (&case.key, &case.error) {
            (Some(key_hex), None) => {
                let key = kobe_vault::prf_key(&prf, &case.info)
                    .unwrap_or_else(|e| panic!("case {index}: prf_key failed: {e}"));
                assert_eq!(hex::encode(*key), key_hex.as_str(), "case {index}");
            }
            (None, Some(error)) => {
                let err = kobe_vault::prf_key(&prf, &case.info)
                    .err()
                    .unwrap_or_else(|| panic!("case {index}: expected error {error}"));
                assert_eq!(err.code().as_str(), error.as_str(), "case {index}");
            }
            _ => panic!("case {index}: malformed prf-key case"),
        }
    }
}

/// `mnemonic` present → success case; `error` present → expected failure code.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasskeyWalletCase {
    prf: String,
    mnemonic: Option<String>,
    seed: Option<String>,
    npub: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PasskeyWalletVector {
    cases: Vec<PasskeyWalletCase>,
}

#[test]
fn passkey_wallet() {
    let vector: PasskeyWalletVector =
        serde_json::from_str(PASSKEY_WALLET).expect("passkey-wallet.json must parse");
    assert!(!vector.cases.is_empty(), "passkey-wallet.json has no cases");
    for (index, case) in vector.cases.iter().enumerate() {
        let prf =
            hex::decode(&case.prf).unwrap_or_else(|_| panic!("case {index}: prf must be hex"));
        match (&case.mnemonic, &case.error) {
            (Some(mnemonic), None) => {
                let wallet = kobe_vault::passkey_wallet(&prf)
                    .unwrap_or_else(|e| panic!("case {index}: passkey_wallet failed: {e}"));
                assert_eq!(wallet.mnemonic(), mnemonic.as_str(), "case {index}");
                assert_eq!(
                    hex::encode(wallet.seed().as_slice()),
                    case.seed.as_deref().unwrap_or_default(),
                    "case {index}"
                );
                let npub = Deriver::new(&wallet)
                    .derive(0)
                    .unwrap_or_else(|e| panic!("case {index}: derive failed: {e}"))
                    .npub()
                    .to_owned();
                assert_eq!(
                    npub.as_str(),
                    case.npub.as_deref().unwrap_or_default(),
                    "case {index}"
                );
            }
            (None, Some(error)) => {
                let err = kobe_vault::passkey_wallet(&prf)
                    .err()
                    .unwrap_or_else(|| panic!("case {index}: expected error {error}"));
                assert_eq!(err.code().as_str(), error.as_str(), "case {index}");
            }
            _ => panic!("case {index}: malformed passkey-wallet case"),
        }
    }
}
