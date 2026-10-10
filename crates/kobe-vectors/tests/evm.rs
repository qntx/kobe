//! Executes `vectors/evm/*.json` against the kobe-evm public API.

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
    reason = "fixture slices are taken at spec offsets"
)]

use kobe_core::{DerivationStyle as _, RecoverableSignature, SecretKey, Wallet};
use kobe_evm::{
    DerivationStyle, Deriver, Signer, authorization_hash, encode_signature,
    encode_signed_transaction, parse_address, personal_message_hash, recover_address, to_checksum,
    transaction_hash, typed_data_hash,
};
use serde::Deserialize;

const DERIVE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/evm/derive.json"
));
const SIGN: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/evm/sign.json"
));
const ENCODE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/evm/encode.json"
));
const EIP712: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/evm/eip712.json"
));
const ADDRESS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/evm/address.json"
));

fn hex_decode(s: &str) -> Vec<u8> {
    hex::decode(s).expect("fixture hex must decode")
}

fn digest(s: &str) -> [u8; 32] {
    let bytes = hex_decode(s);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

#[derive(Debug, Deserialize)]
struct Cases<C> {
    cases: Vec<C>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeriveCase {
    mnemonic: String,
    passphrase: Option<String>,
    style: String,
    index: u32,
    path: String,
    public_key: String,
    address: String,
}

#[test]
fn evm_derive() {
    let vector: Cases<DeriveCase> = serde_json::from_str(DERIVE).expect("derive.json must parse");
    assert!(!vector.cases.is_empty(), "derive.json has no cases");
    for case in &vector.cases {
        let name = format!("{} {}/{}", case.mnemonic, case.style, case.index);
        let wallet = Wallet::from_mnemonic(&case.mnemonic, case.passphrase.as_deref())
            .unwrap_or_else(|e| panic!("{name}: from_mnemonic failed: {e}"));
        let style: DerivationStyle = case
            .style
            .parse()
            .unwrap_or_else(|e| panic!("{name}: bad style: {e}"));
        let account = Deriver::new(&wallet)
            .derive_with(style, case.index)
            .unwrap_or_else(|e| panic!("{name}: derive failed: {e}"));
        assert_eq!(account.path(), case.path.as_str(), "{name}");
        assert_eq!(style.path(case.index), case.path, "{name}");
        assert_eq!(account.address(), case.address.as_str(), "{name}");
        assert_eq!(account.public_key_hex(), case.public_key.as_str(), "{name}");
    }
}

#[derive(Debug, Deserialize)]
struct SignVector {
    #[serde(rename = "secretKey")]
    secret_key: String,
    cases: Vec<SignCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
enum SignCase {
    #[serde(rename = "personal-message")]
    PersonalMessage {
        message: String,
        hash: String,
        signature: String,
        recovery: u8,
        encoded: String,
    },
    #[serde(rename = "authorization")]
    Authorization {
        #[serde(rename = "chainId")]
        chain_id: String,
        address: String,
        nonce: String,
        hash: String,
        signature: String,
        recovery: u8,
        encoded: String,
    },
}

fn address_bytes(s: &str) -> [u8; 20] {
    parse_address(s).expect("fixture address must parse")
}

fn expected_signature(signature: &str, recovery: u8) -> (RecoverableSignature, [u8; 64]) {
    let bytes = hex_decode(signature);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&bytes);
    (
        RecoverableSignature {
            signature: sig,
            recovery,
        },
        sig,
    )
}

#[test]
fn evm_sign() {
    let vector: SignVector = serde_json::from_str(SIGN).expect("sign.json must parse");
    assert!(!vector.cases.is_empty(), "sign.json has no cases");
    let secret = SecretKey::from_bytes(&hex_decode(&vector.secret_key))
        .expect("vector secret key must be valid");
    let signer = Signer::new(&secret).expect("vector secret key must sign");
    for case in &vector.cases {
        match case {
            SignCase::PersonalMessage {
                message,
                hash,
                signature,
                recovery,
                encoded,
            } => {
                let msg = hex_decode(message);
                assert_eq!(
                    personal_message_hash(&msg),
                    digest(hash),
                    "message {message}"
                );
                let sig = signer.sign_personal_message(&msg);
                let (expected, raw) = expected_signature(signature, *recovery);
                assert_eq!(sig, expected, "message {message}");
                assert_eq!(encode_signature(&sig).to_vec(), hex_decode(encoded));
                assert_eq!(
                    recover_address(&digest(hash), &sig).expect("recovery must succeed"),
                    signer.address()
                );
                let _ = raw;
            }
            SignCase::Authorization {
                chain_id,
                address,
                nonce,
                hash,
                signature,
                recovery,
                encoded,
            } => {
                let cid: u64 = chain_id.parse().expect("chainId must parse");
                let n: u64 = nonce.parse().expect("nonce must parse");
                let addr = address_bytes(address);
                assert_eq!(
                    authorization_hash(cid, &addr, n),
                    digest(hash),
                    "authorization {chain_id}/{nonce}"
                );
                let sig = signer.sign_authorization(cid, &addr, n);
                let (expected, _) = expected_signature(signature, *recovery);
                assert_eq!(sig, expected, "authorization {chain_id}/{nonce}");
                assert_eq!(encode_signature(&sig).to_vec(), hex_decode(encoded));
                assert_eq!(
                    recover_address(&digest(hash), &sig).expect("recovery must succeed"),
                    signer.address()
                );
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncodeCase {
    name: String,
    unsigned: String,
    hash: Option<String>,
    signature: Option<String>,
    recovery: Option<u8>,
    signed: Option<String>,
    error: Option<String>,
}

#[test]
fn evm_encode() {
    let vector: Cases<EncodeCase> = serde_json::from_str(ENCODE).expect("encode.json must parse");
    assert!(!vector.cases.is_empty(), "encode.json has no cases");
    for case in &vector.cases {
        let unsigned = hex_decode(&case.unsigned);
        if case.error.is_some() {
            assert!(
                transaction_hash(&unsigned).is_err(),
                "{}: expected transaction_hash error",
                case.name
            );
            let dummy = RecoverableSignature {
                signature: [0u8; 64],
                recovery: 0,
            };
            assert!(
                encode_signed_transaction(&unsigned, &dummy).is_err(),
                "{}: expected encode_signed_transaction error",
                case.name
            );
            continue;
        }
        let hash = case.hash.as_deref().expect("signed case needs hash");
        let signature = case
            .signature
            .as_deref()
            .expect("signed case needs signature");
        let recovery = case.recovery.expect("signed case needs recovery");
        let signed = case.signed.as_deref().expect("signed case needs signed");

        assert_eq!(
            transaction_hash(&unsigned).expect("hash must succeed"),
            digest(hash),
            "{}",
            case.name
        );
        let sig = RecoverableSignature {
            signature: {
                let mut b = [0u8; 64];
                b.copy_from_slice(&hex_decode(signature));
                b
            },
            recovery,
        };
        assert_eq!(
            recover_address(&digest(hash), &sig).expect("recovery must succeed"),
            Signer::new(
                &SecretKey::from_bytes(&hex_decode(
                    "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
                ))
                .expect("KAT key")
            )
            .expect("KAT key")
            .address(),
            "{}",
            case.name
        );
        assert_eq!(
            encode_signed_transaction(&unsigned, &sig).expect("encode must succeed"),
            hex_decode(signed),
            "{}",
            case.name
        );
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Eip712Case {
    name: String,
    typed_data: String,
    hash: Option<String>,
    secret_key: Option<String>,
    signature: Option<String>,
    recovery: Option<u8>,
    error: Option<String>,
}

#[test]
fn evm_eip712() {
    let vector: Cases<Eip712Case> = serde_json::from_str(EIP712).expect("eip712.json must parse");
    assert!(!vector.cases.is_empty(), "eip712.json has no cases");
    let default_key = serde_json::from_str::<SignVector>(SIGN)
        .expect("sign.json must parse")
        .secret_key;
    for case in &vector.cases {
        if case.error.is_some() {
            assert!(
                typed_data_hash(&case.typed_data).is_err(),
                "{}: expected typed_data_hash error",
                case.name
            );
            continue;
        }
        let hash = case.hash.as_deref().expect("signed case needs hash");
        let signature = case
            .signature
            .as_deref()
            .expect("signed case needs signature");
        let recovery = case.recovery.expect("signed case needs recovery");
        let secret_key = case.secret_key.as_deref().unwrap_or(default_key.as_str());

        assert_eq!(
            typed_data_hash(&case.typed_data).expect("hash must succeed"),
            digest(hash),
            "{}",
            case.name
        );
        let signer = Signer::new(
            &SecretKey::from_bytes(&hex_decode(secret_key)).expect("secret key must be valid"),
        )
        .expect("secret key must sign");
        let sig = signer
            .sign_typed_data(&case.typed_data)
            .unwrap_or_else(|e| panic!("{}: sign_typed_data failed: {e}", case.name));
        let (expected, _) = expected_signature(signature, recovery);
        assert_eq!(sig, expected, "{}", case.name);
        assert_eq!(
            recover_address(&digest(hash), &sig).expect("recovery must succeed"),
            signer.address()
        );
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
enum AddressCase {
    #[serde(rename = "parse")]
    Parse {
        address: String,
        error: Option<String>,
    },
    #[serde(rename = "recover")]
    Recover {
        digest: String,
        signature: String,
        recovery: u8,
        address: String,
    },
}

#[test]
fn evm_address() {
    let vector: Cases<AddressCase> =
        serde_json::from_str(ADDRESS).expect("address.json must parse");
    assert!(!vector.cases.is_empty(), "address.json has no cases");
    for case in &vector.cases {
        match case {
            AddressCase::Parse { address, error } => {
                if error.is_some() {
                    assert!(
                        parse_address(address).is_err(),
                        "parse {address}: expected error"
                    );
                    continue;
                }
                let bytes = parse_address(address).expect("parse must succeed");
                assert_eq!(hex::encode(bytes), address[2..].to_lowercase());
                // Mixed-case hex letters (a–f plus A–F) must match EIP-55.
                let hex_part = &address[2..];
                let mixed = hex_part.bytes().any(|b| b.is_ascii_lowercase())
                    && hex_part.bytes().any(|b| b.is_ascii_uppercase());
                if !mixed {
                    continue;
                }
                assert_eq!(to_checksum(&bytes), *address);
            }
            AddressCase::Recover {
                digest: d,
                signature,
                recovery,
                address,
            } => {
                let mut sig = [0u8; 64];
                sig.copy_from_slice(&hex_decode(signature));
                let recovered = recover_address(
                    &digest(d),
                    &RecoverableSignature {
                        signature: sig,
                        recovery: *recovery,
                    },
                )
                .expect("recovery must succeed");
                assert_eq!(recovered, *address);
            }
        }
    }
}
