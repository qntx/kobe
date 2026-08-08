//! Casper account derivation from a unified wallet seed.

use alloc::string::String;
use core::ops::Deref;

use kobe_primitives::{
    DerivationStyle as _, Derive, DeriveError, DerivedAccount, DerivedPublicKey, Wallet,
};

use crate::address::{
    ED25519_TAG, SECP256K1_TAG, account_hash_ed25519, account_hash_secp256k1, format_account_hash,
    tagged_public_key_hex,
};
use crate::key_algo::KeyAlgo;

/// A Casper-specific derived account.
///
/// Wraps the unified [`DerivedAccount`] (`address` = `account-hash-…`) and
/// adds the signature algorithm plus the Casper **tagged** public-key hex
/// (`01…` / `02…`) used in serialization contexts.
///
/// Implements `Deref<Target = DerivedAccount>` so shared accessors
/// (`address()`, `public_key_bytes()`, `private_key_hex()`, …) work directly.
#[derive(Clone)]
pub struct CasperAccount {
    inner: DerivedAccount,
    algo: KeyAlgo,
    /// Lowercase hex of tag ‖ raw public key (no `0x` prefix).
    public_key_hex: String,
}

impl core::fmt::Debug for CasperAccount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CasperAccount")
            .field("inner", &self.inner)
            .field("algo", &self.algo)
            .field("public_key_hex", &self.public_key_hex)
            .finish()
    }
}

impl CasperAccount {
    /// Signature algorithm used for this derivation.
    #[inline]
    #[must_use]
    pub const fn algo(&self) -> KeyAlgo {
        self.algo
    }

    /// Casper tagged public-key hex (`01 ‖ ed25519` or `02 ‖ secp compressed`).
    ///
    /// No `0x` prefix; lowercase.
    ///
    /// **Name collision note:** this inherent method shadows
    /// [`DerivedAccount::public_key_hex`] via `Deref`. Callers that need the
    /// untagged raw curve key must use
    /// `as_derived_account().public_key_hex()` or `public_key().to_hex()`.
    #[inline]
    #[must_use]
    pub fn public_key_hex(&self) -> &str {
        &self.public_key_hex
    }

    /// Alias for [`Self::public_key_hex`] — preferred when reading code next
    /// to untagged [`DerivedAccount::public_key_hex`].
    #[inline]
    #[must_use]
    pub fn tagged_public_key_hex(&self) -> &str {
        &self.public_key_hex
    }

    /// Formatted `AccountHash` (`account-hash-` + 64 hex). Alias for
    /// [`DerivedAccount::address`].
    #[inline]
    #[must_use]
    pub fn account_hash(&self) -> &str {
        self.inner.address()
    }

    /// The underlying unified [`DerivedAccount`].
    #[inline]
    #[must_use]
    pub const fn as_derived_account(&self) -> &DerivedAccount {
        &self.inner
    }

    /// Consume and yield the underlying [`DerivedAccount`].
    #[inline]
    #[must_use]
    pub fn into_derived_account(self) -> DerivedAccount {
        self.inner
    }
}

impl Deref for CasperAccount {
    type Target = DerivedAccount;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl AsRef<DerivedAccount> for CasperAccount {
    #[inline]
    fn as_ref(&self) -> &DerivedAccount {
        &self.inner
    }
}

impl From<CasperAccount> for DerivedAccount {
    #[inline]
    fn from(account: CasperAccount) -> Self {
        account.inner
    }
}

/// Casper address deriver from a unified wallet seed.
///
/// Default algorithm is [`KeyAlgo::Secp256k1`] (Ledger path). Switch with
/// [`with_algo`](Self::with_algo) or per-call [`derive_with`](Self::derive_with).
#[derive(Debug)]
pub struct Deriver<'a> {
    wallet: &'a Wallet,
    algo: KeyAlgo,
}

impl<'a> Deriver<'a> {
    /// Create a deriver with the default algorithm ([`KeyAlgo::Secp256k1`]).
    #[inline]
    #[must_use]
    pub const fn new(wallet: &'a Wallet) -> Self {
        Self {
            wallet,
            algo: KeyAlgo::Secp256k1,
        }
    }

    /// Create a deriver locked to `algo` for [`Derive::derive`] /
    /// [`Derive::derive_path`].
    #[inline]
    #[must_use]
    pub const fn with_algo(wallet: &'a Wallet, algo: KeyAlgo) -> Self {
        Self { wallet, algo }
    }

    /// Algorithm used by [`Derive::derive`] and [`Derive::derive_path`].
    #[inline]
    #[must_use]
    pub const fn algo(&self) -> KeyAlgo {
        self.algo
    }

    /// Derive at the default path for the deriver's algorithm.
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation or `AccountHash` hashing fails.
    #[inline]
    pub fn derive(&self, index: u32) -> Result<CasperAccount, DeriveError> {
        self.derive_with(self.algo, index)
    }

    /// Derive at the default path for an explicit algorithm.
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation or `AccountHash` hashing fails.
    pub fn derive_with(&self, algo: KeyAlgo, index: u32) -> Result<CasperAccount, DeriveError> {
        self.derive_at_with(&algo.path(index), algo)
    }

    /// Derive at an arbitrary path using the deriver's stored algorithm for
    /// tagging / `AccountHash`.
    ///
    /// Prefer [`derive_at_with`](Self::derive_at_with) when the path and
    /// algorithm must be specified together.
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation or `AccountHash` hashing fails.
    #[inline]
    pub fn derive_at(&self, path: &str) -> Result<CasperAccount, DeriveError> {
        self.derive_at_with(path, self.algo)
    }

    /// Derive at an arbitrary path with an explicit algorithm (encoding).
    ///
    /// The path must be valid for the curve of `algo` (BIP-32 for secp,
    /// fully hardened SLIP-10 for Ed25519).
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation or `AccountHash` hashing fails.
    pub fn derive_at_with(&self, path: &str, algo: KeyAlgo) -> Result<CasperAccount, DeriveError> {
        match algo {
            KeyAlgo::Secp256k1 => self.derive_secp(path),
            KeyAlgo::Ed25519 => self.derive_ed25519(path),
        }
    }

    fn derive_secp(&self, path: &str) -> Result<CasperAccount, DeriveError> {
        let key = self.wallet.derive_secp256k1(path)?;
        let compressed = key.compressed_pubkey();
        let digest = account_hash_secp256k1(&compressed)?;
        let address = format_account_hash(&digest);
        let public_key_hex = tagged_public_key_hex(SECP256K1_TAG, &compressed);
        let sk = key.private_key_bytes();

        let inner = DerivedAccount::new(
            String::from(path),
            sk,
            DerivedPublicKey::Secp256k1Compressed(compressed),
            address,
        );

        Ok(CasperAccount {
            inner,
            algo: KeyAlgo::Secp256k1,
            public_key_hex,
        })
    }

    fn derive_ed25519(&self, path: &str) -> Result<CasperAccount, DeriveError> {
        let derived = self.wallet.derive_ed25519(path)?;
        let pubkey_bytes = derived.public_key_bytes();
        let digest = account_hash_ed25519(&pubkey_bytes)?;
        let address = format_account_hash(&digest);
        let public_key_hex = tagged_public_key_hex(ED25519_TAG, &pubkey_bytes);
        let sk_bytes = derived.private_key_bytes();

        let inner = DerivedAccount::new(
            String::from(path),
            sk_bytes,
            DerivedPublicKey::Ed25519(pubkey_bytes),
            address,
        );

        Ok(CasperAccount {
            inner,
            algo: KeyAlgo::Ed25519,
            public_key_hex,
        })
    }
}

impl Derive for Deriver<'_> {
    type Account = CasperAccount;
    type Error = DeriveError;

    fn derive(&self, index: u32) -> Result<CasperAccount, DeriveError> {
        Deriver::derive(self, index)
    }

    fn derive_path(&self, path: &str) -> Result<CasperAccount, DeriveError> {
        self.derive_at(path)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "unit tests"
)]
mod tests {
    use alloc::format;
    use alloc::vec::Vec;

    use kobe_primitives::DeriveExt;

    use super::*;
    use crate::address::{account_hash_ed25519, account_hash_secp256k1, format_account_hash};

    /// Canonical BIP-39 test mnemonic (12 × `abandon` + `about`).
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// Locked HD KAT — abandon @ secp `m/44'/506'/0'/0/0`.
    ///
    /// Private key from workspace BIP-32 (`kobe-primitives`). `AccountHash` via
    /// `casper-types` preimage (`b"secp256k1" || 0x00 || compressed_pk`),
    /// independently re-checked with Python `hashlib.blake2b` over the
    /// public key in `SECP0_TAGGED` (strip leading `02` tag byte).
    const SECP0_PRIV: &str = "9c72144893c3ca5fa7299e65a7d7d6c41ab6a7add5f9860618324854d3c369d1";
    const SECP0_ADDR: &str =
        "account-hash-e699fcd4904aa6617b2930c6d8995a6f301708b6a64621820a5896d92e2457b3";
    const SECP0_TAGGED: &str =
        "020357f9e27d8125932c5e6fd52babb1a114bc89363f2f56c7860bb594f74523342b";

    /// Locked HD KAT — abandon @ ed25519 `m/44'/506'/0'/0'/0'`.
    ///
    /// Private key matches independent Python SLIP-10 (`ed25519 seed` + path).
    /// `AccountHash` re-checked with Python `hashlib.blake2b` over the untagged
    /// public key (`ED0_TAGGED` without leading `01`).
    const ED0_PRIV: &str = "619386127005778f66a68fa91518c0841f59495790bb796fc781ecdd54fe329a";
    const ED0_ADDR: &str =
        "account-hash-356106f683840956a5bff75d011b236068ceccdf09d5c1a6a748c9355b635e08";
    const ED0_TAGGED: &str = "016a1585d8197fc14b1d8cc05d5351e5ba04810d466158a050494c799b776ff819";

    fn test_wallet() -> Wallet {
        Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap()
    }

    /// Default deriver uses secp path and `AccountHash` address.
    #[test]
    fn default_algo_is_secp_path() {
        let a = Deriver::new(&test_wallet()).derive(0).unwrap();
        assert_eq!(a.algo(), KeyAlgo::Secp256k1);
        assert_eq!(a.path(), "m/44'/506'/0'/0/0");
        assert!(a.address().starts_with("account-hash-"));
        assert_eq!(a.address().len(), "account-hash-".len() + 64);
        assert!(a.public_key_hex().starts_with("02"));
        assert_eq!(a.public_key_hex().len(), 2 + 66); // tag + 33-byte key hex
    }

    /// `AccountHash` recomputed from public key bytes must match `address()`.
    #[test]
    fn account_hash_matches_pubkey_encoding_secp() {
        let a = Deriver::new(&test_wallet()).derive(0).unwrap();
        let pk = match a.public_key() {
            DerivedPublicKey::Secp256k1Compressed(b) => b,
            other => panic!("expected compressed secp, got {other:?}"),
        };
        let digest = account_hash_secp256k1(pk).unwrap();
        assert_eq!(a.address(), format_account_hash(&digest));
        assert_eq!(a.public_key_hex(), format!("02{}", hex::encode(pk)));
    }

    #[test]
    fn account_hash_matches_pubkey_encoding_ed25519() {
        let a = Deriver::with_algo(&test_wallet(), KeyAlgo::Ed25519)
            .derive(0)
            .unwrap();
        assert_eq!(a.path(), "m/44'/506'/0'/0'/0'");
        let pk = match a.public_key() {
            DerivedPublicKey::Ed25519(b) => b,
            other => panic!("expected ed25519, got {other:?}"),
        };
        let digest = account_hash_ed25519(pk).unwrap();
        assert_eq!(a.address(), format_account_hash(&digest));
        assert!(a.public_key_hex().starts_with("01"));
        assert_eq!(a.public_key_hex().len(), 2 + 64);
    }

    #[test]
    fn kat_secp_abandon_index0() {
        let a = Deriver::new(&test_wallet()).derive(0).unwrap();
        assert_eq!(a.path(), "m/44'/506'/0'/0/0");
        let sk = a.private_key_hex();
        assert_eq!(sk.as_str(), SECP0_PRIV);
        assert_eq!(a.address(), SECP0_ADDR);
        assert_eq!(a.public_key_hex(), SECP0_TAGGED);
    }

    #[test]
    fn kat_ed25519_abandon_index0() {
        let a = Deriver::with_algo(&test_wallet(), KeyAlgo::Ed25519)
            .derive(0)
            .unwrap();
        assert_eq!(a.path(), "m/44'/506'/0'/0'/0'");
        let sk = a.private_key_hex();
        assert_eq!(sk.as_str(), ED0_PRIV);
        assert_eq!(a.address(), ED0_ADDR);
        assert_eq!(a.public_key_hex(), ED0_TAGGED);
    }

    #[test]
    fn kat_secp_abandon_index1_differs() {
        let w = test_wallet();
        let d = Deriver::new(&w);
        let a0 = d.derive(0).unwrap();
        let a1 = d.derive(1).unwrap();
        assert_ne!(a0.address(), a1.address());
        assert_eq!(a1.path(), "m/44'/506'/0'/0/1");
    }

    #[test]
    fn derive_many_matches_individual() {
        let w = test_wallet();
        let d = Deriver::new(&w);
        let batch = d.derive_many(0, 3).unwrap();
        let single: Vec<_> = (0..3).map(|i| d.derive(i).unwrap()).collect();
        for (b, s) in batch.iter().zip(single.iter()) {
            assert_eq!(b.address(), s.address());
            assert_eq!(b.path(), s.path());
            assert_eq!(b.public_key_hex(), s.public_key_hex());
        }
    }

    #[test]
    fn passphrase_changes_derivation() {
        let w = Wallet::from_mnemonic(TEST_MNEMONIC, Some("TREZOR")).unwrap();
        assert_ne!(
            Deriver::new(&test_wallet()).derive(0).unwrap().address(),
            Deriver::new(&w).derive(0).unwrap().address(),
        );
    }

    #[test]
    fn ed_and_secp_addresses_differ() {
        let w = test_wallet();
        let secp = Deriver::new(&w).derive(0).unwrap();
        let ed = Deriver::with_algo(&w, KeyAlgo::Ed25519).derive(0).unwrap();
        assert_ne!(secp.address(), ed.address());
    }
}
