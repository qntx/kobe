//! Internal key-derivation primitives (BIP-32 secp256k1, SLIP-10 ed25519).

#[cfg(feature = "hd-bip32")]
pub(crate) mod bip32;
#[cfg(feature = "cardano")]
pub(crate) mod cardano;
#[cfg(feature = "hd-slip10")]
pub(crate) mod slip10;
