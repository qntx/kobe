//! Solana address derivation from HD wallet.

use alloc::string::String;
use alloc::vec::Vec;
use core::ops::Deref;

use kobe_primitives::slip10::DerivedKey;
use kobe_primitives::{Derive, DerivedAccount, Wallet, derive_range};
use zeroize::Zeroizing;

use crate::DeriveError;
use crate::derivation_style::DerivationStyle;

/// A Solana-specific derived account — [`DerivedAccount`] plus Phantom-style keypair.
///
/// Wraps the unified [`DerivedAccount`] (path, 32-byte private key, 32-byte
/// public key, Base58 address) and adds the Solana-native 64-byte keypair
/// (`secret || public`) Base58-encoded for Phantom / Backpack / Solflare
/// import.
///
/// Implements `Deref<Target = DerivedAccount>`, so all shared accessors
/// (`address()`, `public_key_bytes()`, etc.) are available directly.
#[derive(Debug, Clone)]
pub struct SvmAccount {
    inner: DerivedAccount,
    keypair_base58: Zeroizing<String>,
}

impl SvmAccount {
    /// Full keypair in Base58 format (64 bytes: secret 32 B + public 32 B), zeroized on drop.
    ///
    /// Standard import format used by Phantom, Backpack, and Solflare.
    #[inline]
    #[must_use]
    pub const fn keypair_base58(&self) -> &Zeroizing<String> {
        &self.keypair_base58
    }

    /// The underlying unified [`DerivedAccount`].
    #[inline]
    #[must_use]
    pub const fn as_derived_account(&self) -> &DerivedAccount {
        &self.inner
    }

    /// Consume and yield the underlying [`DerivedAccount`], dropping the
    /// Solana-specific keypair field.
    #[inline]
    #[must_use]
    pub fn into_derived_account(self) -> DerivedAccount {
        self.inner
    }
}

impl Deref for SvmAccount {
    type Target = DerivedAccount;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl From<SvmAccount> for DerivedAccount {
    #[inline]
    fn from(svm: SvmAccount) -> Self {
        svm.inner
    }
}

/// Solana address deriver from a unified wallet seed.
///
/// This deriver takes a seed from [`kobe_primitives::Wallet`] and derives
/// Solana addresses following BIP44/SLIP-0010 standards.
#[derive(Debug)]
pub struct Deriver<'a> {
    /// Reference to the wallet for seed access.
    wallet: &'a Wallet,
}

impl<'a> Deriver<'a> {
    /// Create a new Solana deriver from a wallet.
    #[inline]
    #[must_use]
    pub const fn new(wallet: &'a Wallet) -> Self {
        Self { wallet }
    }

    /// Derive a Solana account using the Standard derivation style.
    ///
    /// Uses path `m/44'/501'/{index}'/0'` (Phantom, Backpack, Solflare).
    ///
    /// # Errors
    ///
    /// Returns an error if derivation fails.
    #[inline]
    pub fn derive(&self, index: u32) -> Result<SvmAccount, DeriveError> {
        self.derive_with(DerivationStyle::Standard, index)
    }

    /// Derive a Solana account with a specific [`DerivationStyle`].
    ///
    /// Supported path layouts:
    /// - **Standard** (Phantom/Backpack): `m/44'/501'/{index}'/0'`
    /// - **Trust**: `m/44'/501'/{index}'`
    /// - **Ledger Live**: `m/44'/501'/{index}'/0'/0'`
    /// - **Legacy**: `m/501'/{index}'/0'/0'`
    ///
    /// # Errors
    ///
    /// Returns an error if derivation fails.
    pub fn derive_with(
        &self,
        style: DerivationStyle,
        index: u32,
    ) -> Result<SvmAccount, DeriveError> {
        let path = style.path(index);
        let derived = self.wallet.derive_ed25519(&path)?;
        Ok(build_svm_account(&derived, path))
    }

    /// Derive multiple accounts using the Standard derivation style.
    ///
    /// # Errors
    ///
    /// Returns an error if any derivation fails.
    #[inline]
    pub fn derive_many(&self, start: u32, count: u32) -> Result<Vec<SvmAccount>, DeriveError> {
        self.derive_many_with(DerivationStyle::Standard, start, count)
    }

    /// Derive multiple accounts with a specific [`DerivationStyle`].
    ///
    /// # Errors
    ///
    /// Returns an error if any derivation fails.
    pub fn derive_many_with(
        &self,
        style: DerivationStyle,
        start: u32,
        count: u32,
    ) -> Result<Vec<SvmAccount>, DeriveError> {
        derive_range(start, count, |i| self.derive_with(style, i))
    }

    /// Derive an account at a custom SLIP-0010 path.
    ///
    /// **Note**: Ed25519 (Solana) only supports hardened derivation;
    /// all path components are treated as hardened.
    ///
    /// # Errors
    ///
    /// Returns an error if derivation fails.
    pub fn derive_at_path(&self, path: &str) -> Result<SvmAccount, DeriveError> {
        let derived = self.wallet.derive_ed25519(path)?;
        Ok(build_svm_account(&derived, String::from(path)))
    }
}

impl Derive for Deriver<'_> {
    type Error = DeriveError;

    fn derive(&self, index: u32) -> Result<DerivedAccount, DeriveError> {
        Ok(self
            .derive_with(DerivationStyle::Standard, index)?
            .into_derived_account())
    }

    fn derive_path(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        Ok(self.derive_at_path(path)?.into_derived_account())
    }
}

/// Build an [`SvmAccount`] from a raw [`DerivedKey`] and path string.
fn build_svm_account(derived: &DerivedKey, path: String) -> SvmAccount {
    let signing_key = derived.to_signing_key();
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes = verifying_key.as_bytes();

    let mut keypair_bytes = Zeroizing::new([0u8; 64]);
    let (left, right) = keypair_bytes.split_at_mut(32);
    left.copy_from_slice(derived.private_key.as_slice());
    right.copy_from_slice(public_key_bytes);
    let keypair_b58 = bs58::encode(&*keypair_bytes).into_string();

    let mut sk_bytes = Zeroizing::new([0u8; 32]);
    sk_bytes.copy_from_slice(derived.private_key.as_slice());

    let inner = DerivedAccount::new(
        path,
        sk_bytes,
        public_key_bytes.to_vec(),
        bs58::encode(public_key_bytes).into_string(),
    );

    SvmAccount {
        inner,
        keypair_base58: Zeroizing::new(keypair_b58),
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, reason = "test assertions")]
mod tests {
    use super::*;

    /// Canonical BIP-39 test mnemonic (12 × `abandon` + `about`).
    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_wallet() -> Wallet {
        Wallet::from_mnemonic(MNEMONIC, None).unwrap()
    }

    /// Known-answer test on the canonical BIP-39 `abandon…about` mnemonic
    /// at the Phantom / Solflare default path `m/44'/501'/{i}'/0'`.
    ///
    /// Cross-verified with an independent Node.js pipeline
    /// (`bip39 → ed25519-hd-key SLIP-10 → tweetnacl key pair → base58`)
    /// per the Solana wallet adapter defaults documented at
    /// <https://docs.phantom.app/>.
    #[test]
    fn kat_solana_phantom_abandon_index0() {
        let acct = Deriver::new(&test_wallet()).derive(0).unwrap();
        assert_eq!(acct.path(), "m/44'/501'/0'/0'");
        assert_eq!(
            acct.address(),
            "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"
        );
        assert_eq!(
            acct.private_key_hex().as_str(),
            "37df573b3ac4ad5b522e064e25b63ea16bcbe79d449e81a0268d1047948bb445"
        );
    }

    #[test]
    fn kat_solana_phantom_abandon_index1() {
        let acct = Deriver::new(&test_wallet()).derive(1).unwrap();
        assert_eq!(acct.path(), "m/44'/501'/1'/0'");
        assert_eq!(
            acct.address(),
            "Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb"
        );
        assert_eq!(
            acct.private_key_hex().as_str(),
            "ba5e7b6e3680b4eb81db8e54c8e466b2e9a899355888403355d858ab985d2fc4"
        );
    }

    /// Each derivation style must produce a distinct path AND a distinct
    /// address — guards against silent path collisions.
    #[test]
    fn derivation_styles_produce_distinct_addresses() {
        let w = test_wallet();
        let d = Deriver::new(&w);
        let standard = d.derive_with(DerivationStyle::Standard, 0).unwrap();
        let trust = d.derive_with(DerivationStyle::Trust, 0).unwrap();
        let ledger = d.derive_with(DerivationStyle::LedgerLive, 0).unwrap();
        let legacy = d.derive_with(DerivationStyle::Legacy, 0).unwrap();
        assert_eq!(standard.path(), "m/44'/501'/0'/0'");
        assert_eq!(trust.path(), "m/44'/501'/0'");
        assert_eq!(ledger.path(), "m/44'/501'/0'/0'/0'");
        assert_eq!(legacy.path(), "m/501'/0'/0'/0'");
        assert_ne!(standard.address(), trust.address());
        assert_ne!(standard.address(), ledger.address());
        assert_ne!(standard.address(), legacy.address());
        assert_ne!(trust.address(), ledger.address());
    }

    /// `derive_many` must agree with scalar `derive` for every index.
    #[test]
    fn derive_many_matches_individual() {
        let w = test_wallet();
        let d = Deriver::new(&w);
        let batch = d.derive_many(0, 3).unwrap();
        let single: Vec<_> = (0..3).map(|i| d.derive(i).unwrap()).collect();
        for (b, s) in batch.iter().zip(single.iter()) {
            assert_eq!(b.address(), s.address());
            assert_eq!(b.path(), s.path());
            assert_eq!(b.keypair_base58(), s.keypair_base58());
        }
    }

    /// `keypair_base58` must be the solana-CLI-compatible 64-byte
    /// (private || public) base58 encoding; decoding it back must yield
    /// the same 32+32 layout.
    #[test]
    fn keypair_base58_matches_64_byte_layout() {
        let w = test_wallet();
        let acct = Deriver::new(&w).derive(0).unwrap();
        let decoded = bs58::decode(acct.keypair_base58().as_str())
            .into_vec()
            .unwrap();
        assert_eq!(decoded.len(), 64);
        assert_eq!(&decoded[..32], acct.private_key_bytes().as_slice());
        assert_eq!(&decoded[32..], acct.public_key_bytes());
    }
}
