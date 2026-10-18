//! SLIP-10 ed25519 derivation: local HMAC-SHA512, hardened indices only.

use alloc::format;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::{ChildIndex, DerivationPath, Error};

type HmacSha512 = Hmac<Sha512>;

/// A SLIP-10 ed25519 node: 32-byte seed + 32-byte chain code.
pub(crate) struct Node {
    secret: Zeroizing<[u8; 32]>,
    chain_code: Zeroizing<[u8; 32]>,
}

impl Node {
    /// Derive the node at `path` below the master key for `seed`.
    ///
    /// SLIP-10 defines only hardened derivation for ed25519; every index in
    /// `path` must be hardened.
    pub(crate) fn derive(seed: &[u8], path: &DerivationPath) -> Result<Self, Error> {
        let mut node = Self::master(seed)?;
        for index in path.as_slice() {
            if !index.is_hardened() {
                return Err(Error::NotHardened(index.index()));
            }
            node = node.child(*index)?;
        }
        Ok(node)
    }

    /// Master node: `I = HMAC-SHA512(key="ed25519 seed", data=seed)`.
    fn master(seed: &[u8]) -> Result<Self, Error> {
        let mut mac = <HmacSha512 as KeyInit>::new_from_slice(b"ed25519 seed")
            .map_err(|e| Error::InvalidKey(format!("slip10 master: {e}")))?;
        mac.update(seed);
        Ok(Self::from_output(&Zeroizing::new(
            mac.finalize().into_bytes().into(),
        )))
    }

    /// Child derivation at a hardened `index` (serialized via its wire value).
    fn child(&self, index: ChildIndex) -> Result<Self, Error> {
        let mut mac = <HmacSha512 as KeyInit>::new_from_slice(self.chain_code.as_slice())
            .map_err(|e| Error::InvalidKey(format!("slip10 child: {e}")))?;
        mac.update(&[0x00]);
        mac.update(&*self.secret);
        mac.update(&index.wire().to_be_bytes());
        Ok(Self::from_output(&Zeroizing::new(
            mac.finalize().into_bytes().into(),
        )))
    }

    fn from_output(out: &Zeroizing<[u8; 64]>) -> Self {
        let (key, code) = out.split_at(32);
        let mut secret = Zeroizing::new([0u8; 32]);
        let mut chain_code = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(key);
        chain_code.copy_from_slice(code);
        Self { secret, chain_code }
    }

    /// The 32-byte ed25519 secret seed.
    pub(crate) fn secret_key(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.secret)
    }

    /// The 32-byte ed25519 public key.
    pub(crate) fn public_key(&self) -> [u8; 32] {
        let signing = ed25519_dalek::SigningKey::from_bytes(&self.secret);
        signing.verifying_key().to_bytes()
    }

    /// The 32-byte SLIP-10 chain code.
    #[cfg(test)]
    pub(crate) fn chain_code(&self) -> [u8; 32] {
        *self.chain_code
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    const VECTORS: &str = include_str!("../../../../vectors/slip10.json");

    fn field<'a>(case: &'a Value, key: &str) -> &'a str {
        case.get(key).and_then(Value::as_str).unwrap()
    }

    #[test]
    fn slip10_official_vectors() {
        let file: Value = serde_json::from_str(VECTORS).unwrap();
        for case in file.get("cases").and_then(Value::as_array).unwrap() {
            let seed = hex::decode(field(case, "seed")).unwrap();
            let path: DerivationPath = field(case, "path").parse().unwrap();
            let node = Node::derive(&seed, &path).unwrap();
            assert_eq!(
                hex::encode(*node.secret_key()),
                field(case, "private_key"),
                "private key at {:?}",
                field(case, "path")
            );
            assert_eq!(
                hex::encode(node.chain_code()),
                field(case, "chain_code"),
                "chain code at {:?}",
                field(case, "path")
            );
            assert_eq!(
                hex::encode(node.public_key()),
                field(case, "public_key"),
                "public key at {:?}",
                field(case, "path")
            );
        }
    }

    #[test]
    fn unhardened_index_rejected() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let path: DerivationPath = "m/44'/0".parse().unwrap();
        assert!(matches!(
            Node::derive(&seed, &path),
            Err(Error::NotHardened(0))
        ));
    }
}
