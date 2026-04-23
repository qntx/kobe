//! Nostr key derivation from a unified wallet.
//!
//! Implements [NIP-06](https://nips.nostr.com/6) — BIP-32 secp256k1 derivation
//! at path `m/44'/1237'/{account}'/0/0` — and emits [NIP-19](https://nips.nostr.com/19)
//! bech32 entities (`nsec` for the private key, `npub` for the x-only public key).

#[cfg(feature = "alloc")]
use alloc::{format, string::String, vec::Vec};
use core::ops::Deref;

use bech32::{Bech32, Hrp};
pub use kobe_primitives::DerivedAccount;
use kobe_primitives::{Derive, Wallet, derive_range};
use zeroize::Zeroizing;

use crate::DeriveError;

/// NIP-19 human-readable part for secret keys.
pub const NSEC_HRP: &str = "nsec";
/// NIP-19 human-readable part for public keys.
pub const NPUB_HRP: &str = "npub";

/// A Nostr-specific derived account — [`DerivedAccount`] plus NIP-19 `nsec`.
///
/// Wraps the unified [`DerivedAccount`] (path, 32-byte private key, 32-byte
/// x-only public key, `npub1…` address) and adds the NIP-19 `nsec1…` bech32
/// encoding of the private key, zeroized on drop.
///
/// Implements `Deref<Target = DerivedAccount>`, so all shared accessors
/// (`address()`, `public_key_bytes()`, etc.) are available directly.
#[derive(Debug, Clone)]
pub struct NostrAccount {
    inner: DerivedAccount,
    nsec: Zeroizing<String>,
}

impl NostrAccount {
    /// NIP-19 `nsec1…` bech32 encoding of the 32-byte private key, zeroized on drop.
    #[inline]
    #[must_use]
    pub const fn nsec(&self) -> &Zeroizing<String> {
        &self.nsec
    }

    /// NIP-19 `npub1…` bech32 encoding of the x-only public key.
    ///
    /// Alias for [`DerivedAccount::address`] (inherited through `Deref`).
    #[inline]
    #[must_use]
    pub fn npub(&self) -> &str {
        self.inner.address()
    }

    /// The underlying unified [`DerivedAccount`].
    #[inline]
    #[must_use]
    pub const fn as_derived_account(&self) -> &DerivedAccount {
        &self.inner
    }

    /// Consume and yield the underlying [`DerivedAccount`], dropping the
    /// Nostr-specific `nsec` field.
    #[inline]
    #[must_use]
    pub fn into_derived_account(self) -> DerivedAccount {
        self.inner
    }
}

impl Deref for NostrAccount {
    type Target = DerivedAccount;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl From<NostrAccount> for DerivedAccount {
    #[inline]
    fn from(account: NostrAccount) -> Self {
        account.inner
    }
}

/// Nostr address deriver from a unified wallet seed.
///
/// Follows NIP-06 with BIP-32 path `m/44'/1237'/{account}'/0/0`.
#[derive(Debug)]
pub struct Deriver<'a> {
    /// Wallet seed reference.
    wallet: &'a Wallet,
}

impl<'a> Deriver<'a> {
    /// Create a new Nostr deriver from a wallet.
    #[inline]
    #[must_use]
    pub const fn new(wallet: &'a Wallet) -> Self {
        Self { wallet }
    }

    /// Derive a Nostr account at the given NIP-06 `account` index.
    ///
    /// `index` maps to the hardened **account** level of the BIP-32
    /// path (`m/44'/1237'/{index}'/0/0`), not the final address level.
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation or bech32 encoding fails.
    #[inline]
    pub fn derive(&self, index: u32) -> Result<NostrAccount, DeriveError> {
        self.derive_at_path(&format!("m/44'/1237'/{index}'/0/0"))
    }

    /// Derive `count` accounts starting at `start` using the default NIP-06 layout.
    ///
    /// # Errors
    ///
    /// Returns an error if any derivation fails or `start + count` overflows.
    #[inline]
    pub fn derive_many(&self, start: u32, count: u32) -> Result<Vec<NostrAccount>, DeriveError> {
        derive_range(start, count, |i| self.derive(i))
    }

    /// Derive a Nostr account at an arbitrary BIP-32 path.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is invalid or derivation fails.
    pub fn derive_at_path(&self, path: &str) -> Result<NostrAccount, DeriveError> {
        let key = self.wallet.derive_secp256k1(path)?;

        // NIP-19 / BIP-340: the x-only public key is the last 32 bytes of the
        // 33-byte compressed secp256k1 pubkey (the leading 0x02/0x03 parity byte
        // is dropped).
        let compressed = key.compressed_pubkey();
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(
            compressed
                .get(1..)
                .ok_or_else(|| DeriveError::Bech32(String::from("unreachable: short pubkey")))?,
        );

        let npub_hrp = Hrp::parse(NPUB_HRP)
            .map_err(|e| DeriveError::Bech32(format!("invalid npub HRP: {e}")))?;
        let npub = bech32::encode::<Bech32>(npub_hrp, &xonly)
            .map_err(|e| DeriveError::Bech32(format!("npub encoding failed: {e}")))?;

        let nsec_hrp = Hrp::parse(NSEC_HRP)
            .map_err(|e| DeriveError::Bech32(format!("invalid nsec HRP: {e}")))?;
        let sk_bytes = key.private_key_bytes();
        let nsec = bech32::encode::<Bech32>(nsec_hrp, sk_bytes.as_slice())
            .map_err(|e| DeriveError::Bech32(format!("nsec encoding failed: {e}")))?;

        let inner = DerivedAccount::new(String::from(path), sk_bytes, xonly.to_vec(), npub);

        Ok(NostrAccount {
            inner,
            nsec: Zeroizing::new(nsec),
        })
    }
}

impl Derive for Deriver<'_> {
    type Error = DeriveError;

    /// Derive a Nostr account at the given NIP-06 `account` index.
    ///
    /// Returns the unified [`DerivedAccount`]; use [`Deriver::derive`] for the
    /// [`NostrAccount`] newtype that also exposes the NIP-19 `nsec`.
    fn derive(&self, index: u32) -> Result<DerivedAccount, DeriveError> {
        Ok(Deriver::derive(self, index)?.into_derived_account())
    }

    fn derive_path(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        Ok(self.derive_at_path(path)?.into_derived_account())
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, reason = "test assertions")]
mod tests {
    use kobe_primitives::DeriveExt;

    use super::*;

    /// NIP-06 test vector 1.
    const TV1_MNEMONIC: &str =
        "leader monkey parrot ring guide accident before fence cannon height naive bean";
    const TV1_PRIV_HEX: &str = "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a";
    const TV1_NSEC: &str = "nsec10allq0gjx7fddtzef0ax00mdps9t2kmtrldkyjfs8l5xruwvh2dq0lhhkp";
    const TV1_PUB_HEX: &str = "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917";
    const TV1_NPUB: &str = "npub1zutzeysacnf9rru6zqwmxd54mud0k44tst6l70ja5mhv8jjumytsd2x7nu";

    /// NIP-06 test vector 2.
    const TV2_MNEMONIC: &str = "what bleak badge arrange retreat wolf trade produce cricket blur garlic valid proud rude strong choose busy staff weather area salt hollow arm fade";
    const TV2_PRIV_HEX: &str = "c15d739894c81a2fcfd3a2df85a0d2c0dbc47a280d092799f144d73d7ae78add";
    const TV2_NSEC: &str = "nsec1c9wh8xy5eqdzln7n5t0ctgxjcrdug73gp5yj0x03gntn67h83twssdfhel";
    const TV2_PUB_HEX: &str = "d41b22899549e1f3d335a31002cfd382174006e166d3e658e3a5eecdb6463573";
    const TV2_NPUB: &str = "npub16sdj9zv4f8sl85e45vgq9n7nsgt5qphpvmf7vk8r5hhvmdjxx4es8rq74h";

    fn wallet(mnemonic: &str) -> Wallet {
        Wallet::from_mnemonic(mnemonic, None).unwrap()
    }

    #[test]
    fn derive_correct_path() {
        let w = wallet(TV1_MNEMONIC);
        let a = Deriver::new(&w).derive(0).unwrap();
        assert_eq!(a.path(), "m/44'/1237'/0'/0/0");
    }

    #[test]
    fn derive_returns_npub_and_nsec_prefix() {
        let w = wallet(TV1_MNEMONIC);
        let a = Deriver::new(&w).derive(0).unwrap();
        assert!(a.npub().starts_with("npub1"));
        assert!(a.nsec().starts_with("nsec1"));
    }

    #[test]
    fn derive_pubkey_is_xonly_32_bytes() {
        let w = wallet(TV1_MNEMONIC);
        let a = Deriver::new(&w).derive(0).unwrap();
        assert_eq!(a.public_key_bytes().len(), 32);
    }

    #[test]
    fn kat_nip06_vector1() {
        let w = wallet(TV1_MNEMONIC);
        let a = Deriver::new(&w).derive(0).unwrap();
        assert_eq!(a.public_key_hex(), TV1_PUB_HEX);
        assert_eq!(a.npub(), TV1_NPUB);
        assert_eq!(a.address(), TV1_NPUB);
        assert_eq!(a.nsec().as_str(), TV1_NSEC);
    }

    #[test]
    fn kat_nip06_vector1_private_key_hex() {
        // The raw 32-byte private key matches the published vector.
        let w = wallet(TV1_MNEMONIC);
        let a = Deriver::new(&w).derive(0).unwrap();
        assert_eq!(a.private_key_hex().as_str(), TV1_PRIV_HEX);
    }

    #[test]
    fn kat_nip06_vector2() {
        let w = wallet(TV2_MNEMONIC);
        let a = Deriver::new(&w).derive(0).unwrap();
        assert_eq!(a.public_key_hex(), TV2_PUB_HEX);
        assert_eq!(a.address(), TV2_NPUB);
        assert_eq!(a.nsec().as_str(), TV2_NSEC);
    }

    #[test]
    fn kat_nip06_vector2_private_key_hex() {
        let w = wallet(TV2_MNEMONIC);
        let a = Deriver::new(&w).derive(0).unwrap();
        assert_eq!(a.private_key_hex().as_str(), TV2_PRIV_HEX);
    }

    #[test]
    fn derive_many_unique_across_accounts() {
        let w = wallet(TV1_MNEMONIC);
        let d = Deriver::new(&w);
        let accounts = d.derive_many(0, 3).unwrap();
        assert_eq!(accounts.len(), 3);
        assert_eq!(accounts[0].path(), "m/44'/1237'/0'/0/0");
        assert_eq!(accounts[1].path(), "m/44'/1237'/1'/0/0");
        assert_eq!(accounts[2].path(), "m/44'/1237'/2'/0/0");
        assert_ne!(accounts[0].address(), accounts[1].address());
        assert_ne!(accounts[1].address(), accounts[2].address());
    }

    #[test]
    fn derive_many_via_derive_ext_returns_derived_accounts() {
        let w = wallet(TV1_MNEMONIC);
        let d = Deriver::new(&w);
        let accounts: Vec<DerivedAccount> = DeriveExt::derive_many(&d, 0, 2).unwrap();
        assert_eq!(accounts.len(), 2);
        assert!(accounts[0].address().starts_with("npub1"));
    }

    #[test]
    fn deterministic() {
        let w1 = wallet(TV1_MNEMONIC);
        let w2 = wallet(TV1_MNEMONIC);
        let a1 = Deriver::new(&w1).derive(0).unwrap();
        let a2 = Deriver::new(&w2).derive(0).unwrap();
        assert_eq!(a1.address(), a2.address());
        assert_eq!(a1.private_key_hex().as_str(), a2.private_key_hex().as_str());
    }

    #[test]
    fn passphrase_changes_address() {
        let w1 = Wallet::from_mnemonic(TV1_MNEMONIC, None).unwrap();
        let w2 = Wallet::from_mnemonic(TV1_MNEMONIC, Some("pass")).unwrap();
        assert_ne!(
            Deriver::new(&w1).derive(0).unwrap().address(),
            Deriver::new(&w2).derive(0).unwrap().address(),
        );
    }

    #[test]
    fn derive_path_custom() {
        let w = wallet(TV1_MNEMONIC);
        let a = Deriver::new(&w)
            .derive_at_path("m/44'/1237'/5'/0/0")
            .unwrap();
        assert_eq!(a.path(), "m/44'/1237'/5'/0/0");
        assert!(a.address().starts_with("npub1"));
    }
}
