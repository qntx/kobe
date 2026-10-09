//! Executes `vectors/nostr/nip06.json` against the kobe-nostr public API.

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

use kobe_core::Wallet;
use kobe_nostr::Deriver;
use serde::Deserialize;

const NIP06: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nostr/nip06.json"
));

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Nip06Case {
    mnemonic: String,
    passphrase: Option<String>,
    account: u32,
    path: String,
    private_key: String,
    public_key: String,
    nsec: String,
    npub: String,
}

#[derive(Debug, Deserialize)]
struct Nip06Vector {
    cases: Vec<Nip06Case>,
}

#[test]
fn nip06() {
    let vector: Nip06Vector = serde_json::from_str(NIP06).expect("nip06.json must parse");
    assert!(!vector.cases.is_empty(), "nip06.json has no cases");
    for (index, case) in vector.cases.iter().enumerate() {
        let passphrase = case.passphrase.as_deref().filter(|p| !p.is_empty());
        let wallet = Wallet::from_mnemonic(&case.mnemonic, passphrase)
            .unwrap_or_else(|e| panic!("case {index}: from_mnemonic failed: {e}"));
        let account = Deriver::new(&wallet)
            .derive(case.account)
            .unwrap_or_else(|e| panic!("case {index}: derive failed: {e}"));
        assert_eq!(account.path(), case.path.as_str(), "case {index}");
        assert_eq!(
            account.private_key_hex().as_str(),
            case.private_key.as_str(),
            "case {index}"
        );
        assert_eq!(
            account.public_key_hex(),
            case.public_key.as_str(),
            "case {index}"
        );
        assert_eq!(
            account
                .nsec()
                .unwrap_or_else(|e| panic!("case {index}: nsec failed: {e}"))
                .as_str(),
            case.nsec.as_str(),
            "case {index}"
        );
        assert_eq!(account.npub(), case.npub.as_str(), "case {index}");
        assert_eq!(account.address(), case.npub.as_str(), "case {index}");
        assert_eq!(
            account.public_key().kind().as_str(),
            "secp256k1-xonly",
            "case {index}"
        );
    }
}
