//! The derived [`Account`] and its raw [`SecretKey`].

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use zeroize::Zeroizing;

use crate::DerivationPath;

/// Raw secret key material behind an [`Account`].
#[derive(Clone)]
#[non_exhaustive]
pub enum SecretKey {
    /// secp256k1 secret scalar (32 bytes).
    Secp256k1(Zeroizing<[u8; 32]>),
    /// Ed25519 seed (32 bytes).
    Ed25519(Zeroizing<[u8; 32]>),
    /// BIP32-Ed25519 extended key `kL ‖ kR` (64 bytes).
    Ed25519Extended(Zeroizing<[u8; 64]>),
    /// Opaque key material (e.g. an RSA JWK blob).
    Opaque(Zeroizing<Vec<u8>>),
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Secp256k1(_) => "Secp256k1",
            Self::Ed25519(_) => "Ed25519",
            Self::Ed25519Extended(_) => "Ed25519Extended",
            Self::Opaque(_) => "Opaque",
        };
        write!(f, "SecretKey::{kind}([REDACTED])")
    }
}

/// A single derived account on a chain.
///
/// `private_key` is the chain's wallet-import encoding (WIF for Bitcoin,
/// `0x`-hex for EVM, base58 `sk‖pk` for Solana, …). [`secret_key`](Self::secret_key)
/// exposes the raw key material. Both are redacted from [`Debug`] output.
#[derive(Clone)]
#[non_exhaustive]
pub struct Account {
    /// The path this account was derived at.
    pub path: DerivationPath,
    /// Native address string.
    pub address: String,
    /// Native public key, lowercase hex unless noted per chain.
    pub public_key: String,
    /// Wallet-import encoding of the private key (per chain).
    pub private_key: Zeroizing<String>,
    /// Extra chain-specific fields, e.g. a Cardano stake address.
    pub extra: Vec<(&'static str, String)>,
    secret: SecretKey,
}

impl Account {
    /// Construct an account; `extra` starts empty.
    #[allow(dead_code, reason = "used by feature-gated chain modules only")]
    pub(crate) const fn new(
        path: DerivationPath,
        address: String,
        public_key: String,
        private_key: Zeroizing<String>,
        secret: SecretKey,
    ) -> Self {
        Self {
            path,
            address,
            public_key,
            private_key,
            extra: Vec::new(),
            secret,
        }
    }

    /// The raw secret key material.
    #[must_use]
    pub const fn secret_key(&self) -> &SecretKey {
        &self.secret
    }
}

impl fmt::Debug for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Account")
            .field("path", &self.path)
            .field("address", &self.address)
            .field("public_key", &self.public_key)
            .field("private_key", &"[REDACTED]")
            .field("extra", &self.extra)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}
