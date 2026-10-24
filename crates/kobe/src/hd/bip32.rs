//! BIP-32 secp256k1 derivation, layered on the `bip32` crate (k256 backend).

use alloc::format;

use bip32_crate::{ChildNumber, XPrv};
use zeroize::Zeroizing;

use crate::{DerivationPath, Error};

/// A BIP-32 secp256k1 node (extended private key).
pub(crate) struct Node {
    xprv: XPrv,
}

impl Node {
    /// Derive the node at `path` below the master key for `seed`
    /// (BIP-32 accepts 16–64 byte seeds; a 64-byte BIP-39 seed is usual).
    pub(crate) fn derive(seed: &[u8], path: &DerivationPath) -> Result<Self, Error> {
        let mut xprv =
            XPrv::new(seed).map_err(|e| Error::InvalidKey(format!("bip32 master: {e}")))?;
        for index in path.as_slice() {
            // `wire()` carries the hardened bit; the < 2^31 index invariant
            // is guaranteed by `ChildIndex` construction.
            xprv = xprv
                .derive_child(ChildNumber(index.wire()))
                .map_err(|e| Error::InvalidKey(format!("bip32 derive: {e}")))?;
        }
        Ok(Self { xprv })
    }

    /// The 32-byte private key.
    #[allow(
        dead_code,
        reason = "used by every chain; dead when only `camouflage` enables BIP-32"
    )]
    pub(crate) fn private_key(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.xprv.private_key().to_bytes().into())
    }

    /// The 33-byte SEC1-compressed public key.
    #[allow(
        dead_code,
        reason = "used by chains emitting compressed keys; dead under evm-only builds"
    )]
    pub(crate) fn public_key(&self) -> [u8; 33] {
        let point = self.xprv.private_key().verifying_key().to_sec1_point(true);
        let mut out = [0u8; 33];
        out.copy_from_slice(point.as_bytes());
        out
    }

    /// The 65-byte SEC1-uncompressed public key (`0x04 ‖ x ‖ y`).
    #[cfg(any(
        feature = "evm",
        feature = "tron",
        feature = "cosmos",
        feature = "filecoin"
    ))]
    pub(crate) fn public_key_uncompressed(&self) -> [u8; 65] {
        let point = self.xprv.private_key().verifying_key().to_sec1_point(false);
        let mut out = [0u8; 65];
        out.copy_from_slice(point.as_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    const VECTORS: &str = include_str!("../../../../vectors/bip32.json");

    #[test]
    fn bip32_official_vectors() {
        let file: Value = serde_json::from_str(VECTORS).unwrap();
        for case in file.get("cases").and_then(Value::as_array).unwrap() {
            let bytes = hex::decode(case.get("seed").and_then(Value::as_str).unwrap()).unwrap();
            for chain in case.get("chains").and_then(Value::as_array).unwrap() {
                let path: DerivationPath = chain
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap()
                    .parse()
                    .unwrap();
                let node = Node::derive(&bytes, &path).unwrap();
                assert_eq!(
                    node.xprv.to_string(bip32_crate::Prefix::XPRV).as_str(),
                    chain.get("xprv").and_then(Value::as_str).unwrap(),
                    "xprv at {:?}",
                    chain.get("path")
                );
                assert_eq!(
                    node.xprv
                        .public_key()
                        .to_string(bip32_crate::Prefix::XPUB)
                        .as_str(),
                    chain.get("xpub").and_then(Value::as_str).unwrap(),
                    "xpub at {:?}",
                    chain.get("path")
                );
            }
        }
    }
}
