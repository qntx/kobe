//! Bitcoin address derivation from a unified wallet.

#[cfg(feature = "alloc")]
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::marker::PhantomData;
use core::ops::Deref;

use bitcoin::PrivateKey;
use bitcoin::bip32::{ChildNumber, Xpriv};
use bitcoin::key::CompressedPublicKey;
use bitcoin::secp256k1::Secp256k1;
use kobe_primitives::{
    Derive, DeriveError, DerivedAccount, DerivedPublicKey, Wallet, derive_range,
};
use zeroize::Zeroizing;

use crate::address::create_address;
use crate::{AddressType, DerivationPath, Network};

/// Bitcoin address deriver from a unified wallet seed.
///
/// This deriver takes a seed from [`kobe_primitives::Wallet`] and derives
/// Bitcoin addresses following BIP32/44/49/84 standards.
#[derive(Debug)]
pub struct Deriver<'a> {
    /// Master extended private key.
    master_key: Xpriv,
    /// Cached secp256k1 context (~768KB, reused across derivations).
    secp: Secp256k1<bitcoin::secp256k1::All>,
    /// Bitcoin network (mainnet or testnet).
    network: Network,
    /// Phantom data to track wallet lifetime.
    _wallet: PhantomData<&'a Wallet>,
}

/// A Bitcoin-specific derived account — [`DerivedAccount`] plus chain-specific metadata.
///
/// Wraps the unified [`DerivedAccount`] (path, 32-byte private key, 33-byte
/// compressed public key, address string) and adds Bitcoin-only fields:
/// [`WIF`](Self::private_key_wif), [`AddressType`](Self::address_type), and
/// the structured [`DerivationPath`](Self::bip32_path).
///
/// Implements `Deref<Target = DerivedAccount>`, so all shared accessors
/// (`address()`, `public_key_bytes()`, etc.) are available directly.
#[derive(Debug, Clone)]
pub struct BtcAccount {
    inner: DerivedAccount,
    private_key_wif: Zeroizing<String>,
    address_type: AddressType,
    bip32_path: DerivationPath,
}

impl BtcAccount {
    /// Private key in WIF (Wallet Import Format), zeroized on drop.
    #[inline]
    #[must_use]
    pub const fn private_key_wif(&self) -> &Zeroizing<String> {
        &self.private_key_wif
    }

    /// The [`AddressType`] used to derive this account.
    #[inline]
    #[must_use]
    pub const fn address_type(&self) -> AddressType {
        self.address_type
    }

    /// Structured BIP-32 derivation path.
    ///
    /// Access the string form via [`DerivedAccount::path`](Self::path)
    /// (inherited through `Deref`).
    #[inline]
    #[must_use]
    pub const fn bip32_path(&self) -> &DerivationPath {
        &self.bip32_path
    }

    /// The underlying unified [`DerivedAccount`].
    #[inline]
    #[must_use]
    pub const fn as_derived_account(&self) -> &DerivedAccount {
        &self.inner
    }

    /// Consume and yield the underlying [`DerivedAccount`], dropping
    /// Bitcoin-specific metadata.
    #[inline]
    #[must_use]
    pub fn into_derived_account(self) -> DerivedAccount {
        self.inner
    }
}

impl Deref for BtcAccount {
    type Target = DerivedAccount;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl From<BtcAccount> for DerivedAccount {
    #[inline]
    fn from(btc: BtcAccount) -> Self {
        btc.inner
    }
}

impl<'a> Deriver<'a> {
    /// Create a new Bitcoin deriver from a wallet.
    ///
    /// # Errors
    ///
    /// Returns an error if the master key derivation fails.
    #[inline]
    pub fn new(wallet: &'a Wallet, network: Network) -> Result<Self, DeriveError> {
        let master_key = Xpriv::new_master(network.to_bitcoin_network(), wallet.seed().as_slice())
            .map_err(|e| DeriveError::Crypto(alloc::format!("bitcoin bip32 master: {e}")))?;

        Ok(Self {
            master_key,
            secp: Secp256k1::new(),
            network,
            _wallet: PhantomData,
        })
    }

    /// Derive a Bitcoin account using P2WPKH (Native `SegWit`) by default.
    ///
    /// Uses path: `m/84'/0'/0'/0/{index}` for mainnet.
    ///
    /// # Errors
    ///
    /// Returns an error if derivation fails.
    #[inline]
    pub fn derive(&self, index: u32) -> Result<BtcAccount, DeriveError> {
        self.derive_with(AddressType::P2wpkh, index)
    }

    /// Derive a Bitcoin account with a specific [`AddressType`].
    ///
    /// This method supports all four Bitcoin address formats:
    /// - **P2pkh** (Legacy): `m/44'/coin'/0'/0/{index}`
    /// - **`P2shP2wpkh`** (Nested SegWit): `m/49'/coin'/0'/0/{index}`
    /// - **P2wpkh** (Native SegWit): `m/84'/coin'/0'/0/{index}`
    /// - **P2tr** (Taproot): `m/86'/coin'/0'/0/{index}`
    ///
    /// # Errors
    ///
    /// Returns an error if derivation fails.
    #[inline]
    pub fn derive_with(
        &self,
        address_type: AddressType,
        index: u32,
    ) -> Result<BtcAccount, DeriveError> {
        let path = DerivationPath::bip_standard(address_type, self.network, 0, false, index)?;
        self.derive_structured(&path, address_type)
    }

    /// Derive multiple accounts with a specific [`AddressType`].
    ///
    /// # Errors
    ///
    /// Returns an error if any derivation fails.
    pub fn derive_many_with(
        &self,
        address_type: AddressType,
        start: u32,
        count: u32,
    ) -> Result<Vec<BtcAccount>, DeriveError> {
        derive_range(start, count, |i| self.derive_with(address_type, i))
    }

    /// Derive a [`BtcAccount`] at a string BIP-32 path, inferring the
    /// [`AddressType`] from the path's BIP-44 purpose segment.
    ///
    /// Aligned with every other chain's `derive_at(&str)` entry point.
    /// The purpose → type mapping follows [`AddressType::from_purpose`]:
    /// `44' → P2PKH`, `49' → P2SH-P2WPKH`, `84' → P2WPKH`, `86' → P2TR`.
    /// For any other purpose (or a non-hardened first segment) use
    /// [`derive_at_with`](Self::derive_at_with) with an explicit type.
    ///
    /// # Errors
    ///
    /// Returns [`DeriveError::Path`] if the path is malformed or its
    /// purpose does not map to a standard BIP, or [`DeriveError::Crypto`]
    /// if BIP-32 derivation fails.
    pub fn derive_at(&self, path: &str) -> Result<BtcAccount, DeriveError> {
        let parsed = DerivationPath::from_path_str(path)?;
        let address_type = infer_address_type(&parsed).ok_or_else(|| {
            DeriveError::Path(alloc::format!(
                "bitcoin: cannot infer address type from path '{path}'; \
                 purpose must be 44'/49'/84'/86'. \
                 Use Deriver::derive_at_with(path, address_type) for custom paths."
            ))
        })?;
        self.derive_structured(&parsed, address_type)
    }

    /// Derive a [`BtcAccount`] at a string BIP-32 path with an explicit
    /// [`AddressType`].
    ///
    /// Escape hatch for non-standard paths (custom purpose, non-hardened
    /// first segment) that [`derive_at`](Self::derive_at) cannot classify
    /// on its own.
    ///
    /// # Errors
    ///
    /// Returns [`DeriveError::Path`] if the path is malformed, or
    /// [`DeriveError::Crypto`] if BIP-32 derivation fails.
    pub fn derive_at_with(
        &self,
        path: &str,
        address_type: AddressType,
    ) -> Result<BtcAccount, DeriveError> {
        let parsed = DerivationPath::from_path_str(path)?;
        self.derive_structured(&parsed, address_type)
    }

    /// Derive a [`BtcAccount`] at a pre-parsed [`DerivationPath`] with the
    /// requested [`AddressType`].
    ///
    /// Advanced entry point for callers that already hold a structured
    /// path (for instance after validating it once and reusing it across
    /// many derivations); every other `derive_*` method funnels through
    /// here. Most callers want [`derive_at`](Self::derive_at) or
    /// [`derive_at_with`](Self::derive_at_with) instead.
    ///
    /// # Errors
    ///
    /// Returns [`DeriveError::Crypto`] if BIP-32 derivation fails.
    pub fn derive_structured(
        &self,
        path: &DerivationPath,
        address_type: AddressType,
    ) -> Result<BtcAccount, DeriveError> {
        let derived = self
            .master_key
            .derive_priv(&self.secp, path.inner())
            .map_err(|e| DeriveError::Crypto(alloc::format!("bitcoin bip32 derive: {e}")))?;

        let private_key = PrivateKey::new(derived.private_key, self.network.to_bitcoin_network());
        let public_key = CompressedPublicKey::from_private_key(&self.secp, &private_key)
            .map_err(|e| DeriveError::Crypto(alloc::format!("bitcoin secp256k1: {e}")))?;

        let address = create_address(&public_key, self.network, address_type);

        let sk_bytes = Zeroizing::new(derived.private_key.secret_bytes());
        let pk_bytes: [u8; 33] = public_key.to_bytes();

        let inner = DerivedAccount::new(
            path.to_string(),
            sk_bytes,
            DerivedPublicKey::Secp256k1Compressed(pk_bytes),
            address.to_string(),
        );

        Ok(BtcAccount {
            inner,
            private_key_wif: Zeroizing::new(private_key.to_wif()),
            address_type,
            bip32_path: path.clone(),
        })
    }

    /// Get the network.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
    }
}

impl Derive for Deriver<'_> {
    type Account = BtcAccount;
    type Error = DeriveError;

    fn derive(&self, index: u32) -> Result<BtcAccount, DeriveError> {
        self.derive_with(AddressType::P2wpkh, index)
    }

    /// Forwards to [`Deriver::derive_at`].
    ///
    /// See that method for the purpose → [`AddressType`] mapping and the
    /// non-standard-path escape hatch
    /// ([`derive_at_with`](Deriver::derive_at_with)).
    fn derive_path(&self, path: &str) -> Result<BtcAccount, DeriveError> {
        self.derive_at(path)
    }
}

/// Infer the [`AddressType`] from the BIP-44 purpose segment of `path`.
///
/// Returns `None` if the path is empty, its first segment is non-hardened,
/// or the hardened value does not map to a standard BIP purpose.
fn infer_address_type(path: &DerivationPath) -> Option<AddressType> {
    let first = path.inner().into_iter().next()?;
    match first {
        ChildNumber::Hardened { index } => AddressType::from_purpose(*index),
        ChildNumber::Normal { .. } => None,
    }
}

impl AsRef<DerivedAccount> for BtcAccount {
    #[inline]
    fn as_ref(&self) -> &DerivedAccount {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::PrivateKey;
    use kobe_primitives::DeriveExt;

    use super::*;

    /// Canonical BIP-39 test mnemonic (12 × `abandon` + `about`).
    ///
    /// Mnemonic and derived addresses appear on iancoleman.io/bip39, every
    /// hardware wallet vendor test, and the official BIP-84 / BIP-86 test
    /// vectors, so any regression will be immediately obvious to users.
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_wallet() -> Wallet {
        Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap()
    }

    fn deriver(wallet: &Wallet, network: Network) -> Deriver<'_> {
        Deriver::new(wallet, network).unwrap()
    }

    /// BIP-84 (`m/84'/0'/0'/0/{i}`) → native-`SegWit` `bc1q…` addresses.
    /// Cross-verified against `bitcoinjs-lib@p2wpkh` in an independent
    /// Node.js pipeline, matching the BIP-84 test vectors listed at
    /// <https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki>.
    #[test]
    fn kat_bip84_p2wpkh_abandon_index0() {
        let w = test_wallet();
        let a = deriver(&w, Network::Mainnet)
            .derive_with(AddressType::P2wpkh, 0)
            .unwrap();
        assert_eq!(a.path(), "m/84'/0'/0'/0/0");
        assert_eq!(a.address(), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        assert_eq!(a.address_type(), AddressType::P2wpkh);
        assert_eq!(
            a.private_key_hex().as_str(),
            "4604b4b710fe91f584fff084e1a9159fe4f8408fff380596a604948474ce4fa3"
        );
    }

    #[test]
    fn kat_bip84_p2wpkh_abandon_index1() {
        let w = test_wallet();
        let a = deriver(&w, Network::Mainnet)
            .derive_with(AddressType::P2wpkh, 1)
            .unwrap();
        assert_eq!(a.path(), "m/84'/0'/0'/0/1");
        assert_eq!(a.address(), "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g");
    }

    /// BIP-44 (`m/44'/0'/0'/0/{i}`) → legacy P2PKH `1…` addresses.
    #[test]
    fn kat_bip44_p2pkh_abandon_index0() {
        let w = test_wallet();
        let a = deriver(&w, Network::Mainnet)
            .derive_with(AddressType::P2pkh, 0)
            .unwrap();
        assert_eq!(a.path(), "m/44'/0'/0'/0/0");
        assert_eq!(a.address(), "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA");
    }

    /// BIP-49 (`m/49'/0'/0'/0/{i}`) → P2SH-wrapped `SegWit` `3…` addresses.
    #[test]
    fn kat_bip49_p2sh_p2wpkh_abandon_index0() {
        let w = test_wallet();
        let a = deriver(&w, Network::Mainnet)
            .derive_with(AddressType::P2shP2wpkh, 0)
            .unwrap();
        assert_eq!(a.path(), "m/49'/0'/0'/0/0");
        assert_eq!(a.address(), "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf");
    }

    /// BIP-86 (`m/86'/0'/0'/0/{i}`) → single-key Taproot `bc1p…`
    /// addresses. Cross-verified against `bitcoinjs-lib@p2tr`.
    #[test]
    fn kat_bip86_p2tr_abandon_index0() {
        let w = test_wallet();
        let a = deriver(&w, Network::Mainnet)
            .derive_with(AddressType::P2tr, 0)
            .unwrap();
        assert_eq!(a.path(), "m/86'/0'/0'/0/0");
        assert_eq!(
            a.address(),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
    }

    /// Testnet SLIP-44 coin type `1` + BIP-84 bech32 HRP `tb`.
    /// Cross-verified against `bitcoinjs-lib` on `bitcoin.networks.testnet`.
    #[test]
    fn kat_testnet_p2wpkh_abandon_index0() {
        let w = test_wallet();
        let a = deriver(&w, Network::Testnet)
            .derive_with(AddressType::P2wpkh, 0)
            .unwrap();
        assert_eq!(a.path(), "m/84'/1'/0'/0/0");
        assert_eq!(a.address(), "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl");
    }

    /// `Derive::derive` (the trait) and `Deriver::derive` (inherent) must
    /// both route to P2WPKH with BIP-84 paths.
    #[test]
    fn default_derive_uses_bip84_p2wpkh() {
        let w = test_wallet();
        let d = deriver(&w, Network::Mainnet);
        let def = d.derive(0).unwrap();
        let explicit = d.derive_with(AddressType::P2wpkh, 0).unwrap();
        assert_eq!(def.address(), explicit.address());
        assert_eq!(def.path(), explicit.path());
    }

    /// `derive_many` must agree with scalar `derive_with` for every index.
    #[test]
    fn derive_many_matches_individual() {
        let w = test_wallet();
        let d = deriver(&w, Network::Mainnet);
        let batch = d.derive_many(0, 5).unwrap();
        let single: Vec<_> = (0..5)
            .map(|i| d.derive_with(AddressType::P2wpkh, i).unwrap())
            .collect();
        for (b, s) in batch.iter().zip(single.iter()) {
            assert_eq!(b.address(), s.address());
            assert_eq!(b.path(), s.path());
        }
    }

    /// WIF must round-trip back to the same 32-byte private key — guards
    /// against checksum or version-byte errors in the WIF encoder.
    #[test]
    fn wif_roundtrips_to_private_key_bytes() {
        let w = test_wallet();
        let a = deriver(&w, Network::Mainnet).derive(0).unwrap();
        let pk = PrivateKey::from_wif(a.private_key_wif().as_str()).unwrap();
        assert_eq!(&pk.to_bytes(), a.private_key_bytes().as_slice());
        assert_eq!(pk.network, bitcoin::NetworkKind::Main);
    }

    #[test]
    fn passphrase_changes_derivation() {
        let w = Wallet::from_mnemonic(TEST_MNEMONIC, Some("TREZOR")).unwrap();
        assert_ne!(
            deriver(&test_wallet(), Network::Mainnet)
                .derive(0)
                .unwrap()
                .address(),
            deriver(&w, Network::Mainnet).derive(0).unwrap().address(),
        );
    }

    /// `Derive::derive_path` must infer the [`AddressType`] from the purpose
    /// segment so that `m/44'` → P2PKH, `m/49'` → P2SH-P2WPKH, `m/84'` → P2WPKH,
    /// and `m/86'` → P2TR on the canonical `abandon…about` mnemonic. Regression
    /// test against the previous hard-coded P2WPKH behaviour, which produced
    /// `bc1q…` for BIP-44/49/86 paths and silently misrepresented user intent.
    #[test]
    fn derive_path_infers_address_type_from_purpose() {
        let w = test_wallet();
        let d = deriver(&w, Network::Mainnet);

        let legacy = d.derive_path("m/44'/0'/0'/0/0").unwrap();
        assert_eq!(legacy.address_type(), AddressType::P2pkh);
        assert!(legacy.address().starts_with('1'));

        let nested = d.derive_path("m/49'/0'/0'/0/0").unwrap();
        assert_eq!(nested.address_type(), AddressType::P2shP2wpkh);
        assert!(nested.address().starts_with('3'));

        let native = d.derive_path("m/84'/0'/0'/0/0").unwrap();
        assert_eq!(native.address_type(), AddressType::P2wpkh);
        assert!(native.address().starts_with("bc1q"));

        let taproot = d.derive_path("m/86'/0'/0'/0/0").unwrap();
        assert_eq!(taproot.address_type(), AddressType::P2tr);
        assert!(taproot.address().starts_with("bc1p"));
    }

    /// Non-standard paths (unknown purpose or non-hardened first segment)
    /// must surface a [`DeriveError::Path`] that points callers at
    /// [`Deriver::derive_at_with`], rather than silently defaulting to
    /// P2WPKH.
    #[test]
    fn derive_path_rejects_non_standard_purpose() {
        let w = test_wallet();
        let d = deriver(&w, Network::Mainnet);

        let unknown_purpose_err = d.derive_path("m/1'/2'/3'").unwrap_err();
        let DeriveError::Path(msg) = &unknown_purpose_err else {
            unreachable!("expected DeriveError::Path, got {unknown_purpose_err:?}");
        };
        assert!(
            msg.contains("cannot infer address type"),
            "unexpected error message: {msg}"
        );
        assert!(
            msg.contains("derive_at_with"),
            "error must point users at Deriver::derive_at_with: {msg}"
        );

        let non_hardened_err = d.derive_path("m/44/0'/0'/0/0").unwrap_err();
        let DeriveError::Path(_) = &non_hardened_err else {
            unreachable!(
                "non-hardened purpose must fail with Path error, got {non_hardened_err:?}"
            );
        };
    }

    /// `derive_at` mirrors `Derive::derive_path` — sanity-check they agree
    /// byte-for-byte on every BIP purpose, so downstream code can pick
    /// either entry point without behavioural drift.
    #[test]
    fn derive_at_matches_trait_derive_path() {
        let w = test_wallet();
        let d = deriver(&w, Network::Mainnet);
        for path in [
            "m/44'/0'/0'/0/0",
            "m/49'/0'/0'/0/0",
            "m/84'/0'/0'/0/0",
            "m/86'/0'/0'/0/0",
        ] {
            let trait_acct = d.derive_path(path).unwrap();
            let inherent_acct = d.derive_at(path).unwrap();
            assert_eq!(trait_acct.address(), inherent_acct.address(), "path={path}");
            assert_eq!(
                trait_acct.address_type(),
                inherent_acct.address_type(),
                "path={path}",
            );
        }
    }

    /// `derive_at_with` is the escape hatch for non-standard paths and
    /// must succeed where `derive_at` would reject the purpose. We also
    /// check that the requested `AddressType` overrides any inference —
    /// here we ask for P2TR at a BIP-84 path on purpose.
    #[test]
    fn derive_at_with_accepts_non_standard_purpose() {
        let w = test_wallet();
        let d = deriver(&w, Network::Mainnet);

        // Non-standard purpose 7' — `derive_at` can't classify it, but
        // `derive_at_with` must work with an explicit AddressType.
        let acct = d
            .derive_at_with("m/7'/0'/0'/0/0", AddressType::P2wpkh)
            .unwrap();
        assert_eq!(acct.path(), "m/7'/0'/0'/0/0");
        assert_eq!(acct.address_type(), AddressType::P2wpkh);
        assert!(acct.address().starts_with("bc1q"));

        // Explicit AddressType must override the purpose hint on a
        // standard path too (BIP-84 path → P2TR if the caller insists).
        let override_acct = d
            .derive_at_with("m/84'/0'/0'/0/0", AddressType::P2tr)
            .unwrap();
        assert_eq!(override_acct.address_type(), AddressType::P2tr);
        assert!(override_acct.address().starts_with("bc1p"));
    }

    /// `derive_structured` is the low-level entry point; when fed a
    /// pre-parsed path it must produce the same account as
    /// `derive_at_with` given the same string.
    #[test]
    fn derive_structured_matches_derive_at_with() {
        let w = test_wallet();
        let d = deriver(&w, Network::Mainnet);
        let path_str = "m/84'/0'/0'/0/0";
        let parsed = DerivationPath::from_path_str(path_str).unwrap();
        let structured = d.derive_structured(&parsed, AddressType::P2wpkh).unwrap();
        let at_with = d.derive_at_with(path_str, AddressType::P2wpkh).unwrap();
        assert_eq!(structured.address(), at_with.address());
        assert_eq!(structured.path(), at_with.path());
    }
}
