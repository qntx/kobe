//! EVM signing: transactions, personal messages, typed data, authorizations.

use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt;

use sha3::{Digest, Keccak256};

use kobe_core::{Error, RecoverableSignature, Secp256k1Signer, SecretKey};

use crate::{address::address_from_uncompressed, eip712, rlp, to_checksum};

const TX_TYPE_EIP2930: u8 = 0x01;
const TX_TYPE_EIP1559: u8 = 0x02;
const TX_TYPE_EIP7702: u8 = 0x04;
const MAGIC_7702: u8 = 0x05;

/// Signer for EVM operations.
///
/// The EVM owns the hash for every operation — the caller hands over the raw
/// transaction, message, typed data or authorization and the signer hashes the
/// full payload before producing a recoverable signature.
pub struct Signer {
    inner: Secp256k1Signer,
}

impl fmt::Debug for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Signer([REDACTED])")
    }
}

impl Signer {
    /// Create a signer from a 32-byte secret key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] when the scalar is zero or out of range.
    pub fn new(secret: &SecretKey) -> Result<Self, Error> {
        Secp256k1Signer::new(secret).map(|inner| Self { inner })
    }

    /// Compressed secp256k1 public key (33 bytes).
    #[must_use]
    pub fn public_key(&self) -> [u8; 33] {
        self.inner.compressed_public_key()
    }

    /// EIP-55 checksummed address derived from the public key.
    #[must_use]
    pub fn address(&self) -> String {
        address_from_uncompressed(&self.inner.uncompressed_public_key())
    }

    /// Hash and sign an unsigned RLP transaction envelope.
    ///
    /// Accepts typed (`0x01`/`0x02`/`0x04` followed by an RLP list) and legacy
    /// EIP-155 envelopes (a bare 9-item RLP list whose last two items are
    /// empty). See [`transaction_hash`] for the envelope rules.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Input`] on a malformed or unsupported envelope.
    pub fn sign_transaction(&self, unsigned: &[u8]) -> Result<RecoverableSignature, Error> {
        let digest = transaction_hash(unsigned)?;
        Ok(self.inner.sign_recoverable(&digest))
    }

    /// Sign an EIP-191 personal message (`\x19Ethereum Signed Message:` prefix).
    #[must_use]
    pub fn sign_personal_message(&self, message: &[u8]) -> RecoverableSignature {
        self.inner.sign_recoverable(&personal_message_hash(message))
    }

    /// Hash and sign an EIP-712 typed-data JSON document (v4).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Input`] on malformed JSON or invalid typed data.
    pub fn sign_typed_data(&self, typed_data_json: &str) -> Result<RecoverableSignature, Error> {
        let digest = typed_data_hash(typed_data_json)?;
        Ok(self.inner.sign_recoverable(&digest))
    }

    /// Sign an EIP-7702 authorization tuple `(chain_id, address, nonce)`.
    #[must_use]
    pub fn sign_authorization(
        &self,
        chain_id: u64,
        address: &[u8; 20],
        nonce: u64,
    ) -> RecoverableSignature {
        self.inner
            .sign_recoverable(&authorization_hash(chain_id, address, nonce))
    }
}

/// Hash of an unsigned transaction envelope — `keccak256` of the bytes as
/// given — after validating the envelope shape.
///
/// Envelope rules (all failures [`Error::Input`]):
///
/// - Typed: first byte `0x01` (EIP-2930), `0x02` (EIP-1559) or `0x04`
///   (EIP-7702) followed by one well-formed RLP list spanning the rest of the
///   bytes exactly. `0x03` (EIP-4844) and any other type byte are rejected.
/// - Legacy: a bare RLP list with exactly 9 items — the EIP-155 unsigned form
///   `[nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]` — whose
///   last two items are empty and whose `chainId` fits in a `u64`. A 6-item
///   pre-EIP-155 list is rejected.
///
/// # Errors
///
/// Returns [`Error::Input`] on a malformed or unsupported envelope.
pub fn transaction_hash(unsigned: &[u8]) -> Result<[u8; 32], Error> {
    validate_envelope(unsigned)?;
    Ok(keccak256(unsigned))
}

/// `keccak256("\x19Ethereum Signed Message:\n" || len || message)`.
#[must_use]
pub fn personal_message_hash(message: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(26 + 5 + message.len());
    buf.extend_from_slice(b"\x19Ethereum Signed Message:\n");
    buf.extend_from_slice(message.len().to_string().as_bytes());
    buf.extend_from_slice(message);
    keccak256(&buf)
}

/// EIP-712 v4 hash of a typed-data JSON document.
///
/// # Errors
///
/// Returns [`Error::Input`] on malformed JSON or invalid typed data.
pub fn typed_data_hash(typed_data_json: &str) -> Result<[u8; 32], Error> {
    eip712::hash_typed_data_json(typed_data_json)
}

/// EIP-7702 authorization hash: `keccak256(0x05 ‖ rlp([chain_id, address, nonce]))`.
#[must_use]
pub fn authorization_hash(chain_id: u64, address: &[u8; 20], nonce: u64) -> [u8; 32] {
    let mut items = Vec::new();
    items.extend_from_slice(&rlp::encode_u64(chain_id));
    items.extend_from_slice(&rlp::encode_bytes(address));
    items.extend_from_slice(&rlp::encode_u64(nonce));

    let mut buf = Vec::with_capacity(1 + items.len() + 5);
    buf.push(MAGIC_7702);
    buf.extend_from_slice(&rlp::encode_list(&items));
    keccak256(&buf)
}

/// Encode a fully signed transaction envelope from its unsigned form.
///
/// - Typed (`0x01`/`0x02`/`0x04`): `type ‖ rlp([…fields, yParity, r, s])`
///   where `yParity` is the raw recovery bit (`0` encodes as `0x80`).
/// - Legacy: `rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s])`
///   with `v = chain_id * 2 + 35 + recovery` (EIP-155).
///
/// `r` and `s` are encoded with leading zeros stripped.
///
/// # Errors
///
/// Returns [`Error::Input`] on a malformed envelope or a 6-item legacy list.
pub fn encode_signed_transaction(
    unsigned: &[u8],
    signature: &RecoverableSignature,
) -> Result<Vec<u8>, Error> {
    let (r, s) = signature.signature.split_at(32);
    match unsigned.first() {
        Some(&(TX_TYPE_EIP2930 | TX_TYPE_EIP1559 | TX_TYPE_EIP7702)) => {
            rlp::encode_signed_typed_tx(unsigned, signature.recovery, r, s).map_err(Error::from)
        }
        Some(&b) if b >= 0xc0 => {
            let payload = rlp::decode_list(unsigned).map_err(Error::from)?;
            let items = rlp::list_items(payload).map_err(Error::from)?;
            let chain_id = validate_legacy_items(&items)?;
            rlp::encode_signed_legacy_tx(payload, chain_id, signature.recovery, r, s)
                .map_err(Error::from)
        }
        Some(_) => Err(Error::Input("unsupported transaction type".into())),
        None => Err(Error::Input("empty transaction".into())),
    }
}

/// 65-byte wire form `r ‖ s ‖ (27 + recovery)` used by EIP-191 / EIP-712.
#[must_use]
pub fn encode_signature(signature: &RecoverableSignature) -> [u8; 65] {
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&signature.signature);
    out[64] = 27 + signature.recovery;
    out
}

/// Recover the EIP-55 checksummed signer address from a digest and a
/// recoverable signature.
///
/// # Errors
///
/// Returns [`Error::Input`] on a malformed signature or failed recovery.
pub fn recover_address(
    digest: &[u8; 32],
    signature: &RecoverableSignature,
) -> Result<String, Error> {
    if signature.recovery > 1 {
        return Err(Error::Input("recovery must be 0 or 1".into()));
    }
    let sig = k256::ecdsa::Signature::from_slice(&signature.signature)
        .map_err(|_| Error::Input("malformed signature".into()))?;
    let recid = k256::ecdsa::RecoveryId::new(signature.recovery == 1, false);
    let key = k256::ecdsa::VerifyingKey::recover_from_prehash(digest, &sig, recid)
        .map_err(|_| Error::Input("signature recovery failed".into()))?;
    let point = key.to_sec1_point(false);
    let bytes: &[u8; 65] = point
        .as_bytes()
        .try_into()
        .map_err(|_| Error::Input("malformed recovered public key".into()))?;
    Ok(address_from_uncompressed(bytes))
}

/// Parse an Ethereum address string into 20 bytes.
///
/// Accepts `"0x"` + 40 hex characters. Mixed-case input must match the EIP-55
/// checksum; all-lowercase and all-uppercase input is accepted without a
/// checksum.
///
/// # Errors
///
/// Returns [`Error::Input`] on bad length, missing `0x`, non-hex characters or
/// a checksum mismatch.
pub fn parse_address(address: &str) -> Result<[u8; 20], Error> {
    let hex_part = address
        .strip_prefix("0x")
        .ok_or_else(|| Error::Input("address must start with 0x".into()))?;
    if hex_part.len() != 40 {
        return Err(Error::Input("address must be 40 hex characters".into()));
    }
    let mut out = [0u8; 20];
    hex::decode_to_slice(hex_part, &mut out)
        .map_err(|_| Error::Input("address contains non-hex characters".into()))?;

    // `decode_to_slice` already proved the input is hex, so ASCII case is
    // enough to detect mixed-case.
    let has_lower = hex_part.bytes().any(|b| b.is_ascii_lowercase());
    let has_upper = hex_part.bytes().any(|b| b.is_ascii_uppercase());
    if has_lower && has_upper && to_checksum(&out) != address {
        return Err(Error::Input("EIP-55 checksum mismatch".into()));
    }
    Ok(out)
}

fn validate_envelope(unsigned: &[u8]) -> Result<(), Error> {
    match unsigned.split_first() {
        Some((&(TX_TYPE_EIP2930 | TX_TYPE_EIP1559 | TX_TYPE_EIP7702), rest)) => {
            rlp::decode_list(rest).map(|_| ()).map_err(Error::from)
        }
        Some((&b, _)) if b >= 0xc0 => {
            let payload = rlp::decode_list(unsigned).map_err(Error::from)?;
            let items = rlp::list_items(payload).map_err(Error::from)?;
            validate_legacy_items(&items).map(|_| ())
        }
        Some(_) => Err(Error::Input("unsupported transaction type".into())),
        None => Err(Error::Input("empty transaction".into())),
    }
}

/// Validate the 9-item EIP-155 unsigned form and return its chain id.
fn validate_legacy_items(items: &[&[u8]]) -> Result<u64, Error> {
    match items.len() {
        9 => {}
        6 => {
            return Err(Error::Input(
                "legacy transaction must carry an EIP-155 chain id".into(),
            ));
        }
        _ => {
            return Err(Error::Input(
                "legacy transaction must contain 9 fields".into(),
            ));
        }
    }
    let &[_, _, _, _, _, _, chain_item, pad_r, pad_s] = items
        .first_chunk::<9>()
        .ok_or_else(|| Error::Input("legacy transaction must contain 9 fields".into()))?;
    if !rlp::is_rlp_zero(pad_r) || !rlp::is_rlp_zero(pad_s) {
        return Err(Error::Input(
            "legacy EIP-155 placeholder fields must be empty".into(),
        ));
    }
    decode_chain_id(chain_item)
}

fn decode_chain_id(item: &[u8]) -> Result<u64, Error> {
    let payload = rlp::item_payload(item).map_err(Error::from)?;
    if payload.len() > 8 {
        return Err(Error::Input("legacy chain id exceeds u64".into()));
    }
    let mut id = 0u64;
    for &b in payload {
        id = (id << 8) | u64::from(b);
    }
    Ok(id)
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    reason = "test assertions use indexing for clarity"
)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    fn kat_secret() -> SecretKey {
        let bytes = hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
            .unwrap();
        SecretKey::from_bytes(&bytes).unwrap()
    }

    const ADDRESS: &str = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23";

    fn unsigned_eip1559() -> Vec<u8> {
        // 0x02 || rlp([chainId=1, nonce=0, tip=0, fee=0, gas=21000,
        //               to="", value=0, data="", accessList=[]])
        let items: Vec<u8> = [
            rlp::encode_u64(1),
            rlp::encode_u64(0),
            rlp::encode_u64(0),
            rlp::encode_u64(0),
            rlp::encode_u64(21_000),
            rlp::encode_bytes(&[]),
            rlp::encode_u64(0),
            rlp::encode_bytes(&[]),
            rlp::encode_list(&[]),
        ]
        .concat();
        let mut tx = vec![0x02];
        tx.extend_from_slice(&rlp::encode_list(&items));
        tx
    }

    #[test]
    fn kat_personal_message_signs_correctly() {
        let signer = Signer::new(&kat_secret()).unwrap();
        let sig = signer.sign_personal_message(b"signer kat v3");
        assert_eq!(
            hex::encode(encode_signature(&sig)),
            "bd238f0d6957ec577e5f90d781f63ff97e730ad39007e4bdde7b903af5f448762\
             e2ef82e254d3c17337883c34a74d9fb0399226f818e4d1621377107f465f6901c"
        );
    }

    #[test]
    fn personal_message_kat_vector() {
        let digest = personal_message_hash(b"signer kat v3");
        assert_eq!(
            hex::encode(digest),
            "56db82ebe75f3f98e4c22251bff0003fb75b5b330b62acb24f0588ed79e45f53"
        );
        assert_eq!(personal_message_hash(b"signer kat v3"), digest);
    }

    #[test]
    fn sign_transaction_deterministic_and_recoverable() {
        let signer = Signer::new(&kat_secret()).unwrap();
        let unsigned = unsigned_eip1559();
        let sig = signer.sign_transaction(&unsigned).unwrap();
        let sig2 = signer.sign_transaction(&unsigned).unwrap();
        assert_eq!(sig, sig2);
        let digest = transaction_hash(&unsigned).unwrap();
        assert_eq!(recover_address(&digest, &sig).unwrap(), signer.address());
    }

    #[test]
    fn sign_transaction_rejects_bad_envelopes() {
        let signer = Signer::new(&kat_secret()).unwrap();
        // EIP-4844 type byte.
        assert!(signer.sign_transaction(&[0x03, 0xc0]).is_err());
        // 6-item pre-EIP-155 legacy list.
        let six = rlp::encode_list(
            &[
                rlp::encode_u64(0),
                rlp::encode_u64(1),
                rlp::encode_u64(21_000),
                rlp::encode_bytes(&[]),
                rlp::encode_u64(0),
                rlp::encode_bytes(&[]),
            ]
            .concat(),
        );
        assert!(signer.sign_transaction(&six).is_err());
        // Truncated RLP payload.
        let mut tx = unsigned_eip1559();
        tx.truncate(tx.len() - 1);
        assert!(signer.sign_transaction(&tx).is_err());
        // Empty input.
        assert!(signer.sign_transaction(&[]).is_err());
    }

    #[test]
    fn sign_auth_produces_deterministic_output() {
        let signer = Signer::new(&kat_secret()).unwrap();
        let addr = hex::decode("0000000000000000000000000000000000000001").unwrap();
        let address: &[u8; 20] = addr.as_slice().try_into().unwrap();
        let s1 = signer.sign_authorization(1, address, 0);
        let s2 = signer.sign_authorization(1, address, 0);
        assert_eq!(s1, s2);
        let digest = authorization_hash(1, address, 0);
        assert_eq!(recover_address(&digest, &s1).unwrap(), signer.address());
    }

    #[test]
    fn typed_data_rejects_invalid_json() {
        let signer = Signer::new(&kat_secret()).unwrap();
        assert!(signer.sign_typed_data("not json").is_err());
    }

    #[test]
    fn encode_signed_transaction_appends_signature() {
        let signer = Signer::new(&kat_secret()).unwrap();
        let unsigned = unsigned_eip1559();
        let sig = signer.sign_transaction(&unsigned).unwrap();
        let signed = encode_signed_transaction(&unsigned, &sig).unwrap();
        assert_eq!(signed[0], 0x02);
        assert!(signed.len() > unsigned.len());
        // Decoding the signed list must yield 12 items (9 unsigned + 3 sig).
        let payload = rlp::decode_list(&signed[1..]).unwrap();
        assert_eq!(rlp::list_items(payload).unwrap().len(), 12);
    }

    #[test]
    fn parse_address_checksum_rules() {
        // EIP-55 spec vector, correct checksum.
        assert!(parse_address("0x52908400098527886E0F7030069857D2E4169EE7").is_ok());
        // Same address all-lower / all-upper is accepted without checksum.
        assert!(parse_address("0x52908400098527886e0f7030069857d2e4169ee7").is_ok());
        assert!(parse_address("0x52908400098527886E0F7030069857D2E4169EE7").is_ok());
        // Bad checksum on mixed case.
        assert!(parse_address("0x52908400098527886E0F7030069857d2E4169EE7").is_err());
        // Bad shapes.
        assert!(parse_address("52908400098527886E0F7030069857D2E4169EE7").is_err());
        assert!(parse_address("0x52908400098527886E0F7030069857D2E4169EE").is_err());
        assert!(parse_address("0xzz908400098527886E0F7030069857D2E4169EE7").is_err());
    }

    #[test]
    fn erc20_transfer_typed_data() {
        let json = r#"{
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                "Transfer": [
                    {"name": "to", "type": "address"},
                    {"name": "amount", "type": "uint256"}
                ]
            },
            "primaryType": "Transfer",
            "domain": {
                "name": "MyToken",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
            },
            "message": {
                "to": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
                "amount": "1000000000000000000"
            }
        }"#;
        let hash = typed_data_hash(json).unwrap();
        let signer = Signer::new(&kat_secret()).unwrap();
        let sig = signer.sign_typed_data(json).unwrap();
        assert_eq!(recover_address(&hash, &sig).unwrap(), signer.address());
    }

    #[test]
    fn recovers_expected_address() {
        let signer = Signer::new(&kat_secret()).unwrap();
        assert_eq!(signer.address(), ADDRESS);
    }
}
