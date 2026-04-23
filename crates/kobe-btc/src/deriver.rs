//! Bitcoin address derivation from a unified wallet.

#[cfg(feature = "alloc")]
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::marker::PhantomData;
use core::ops::Deref;

use bitcoin::PrivateKey;
use bitcoin::bip32::Xpriv;
use bitcoin::key::CompressedPublicKey;
use bitcoin::secp256k1::Secp256k1;
use kobe_primitives::{Derive, DerivedAccount, Wallet};
use zeroize::Zeroizing;

use crate::address::create_address;
use crate::{AddressType, DerivationPath, DeriveError, Network};

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
        let master_key = Xpriv::new_master(network.to_bitcoin_network(), wallet.seed())?;

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
        self.derive_bip32_path(&path, address_type)
    }

    /// Derive multiple accounts using P2WPKH (Native `SegWit`) by default.
    ///
    /// # Errors
    ///
    /// Returns an error if any derivation fails.
    #[inline]
    pub fn derive_many(&self, start: u32, count: u32) -> Result<Vec<BtcAccount>, DeriveError> {
        self.derive_many_with(AddressType::P2wpkh, start, count)
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
        let end = start.checked_add(count).ok_or_else(|| {
            DeriveError::InvalidDerivationPath(
                "index overflow: start + count exceeds u32::MAX".into(),
            )
        })?;
        (start..end)
            .map(|index| self.derive_with(address_type, index))
            .collect()
    }

    /// Derive a [`BtcAccount`] at a structured [`DerivationPath`] with the
    /// requested [`AddressType`].
    ///
    /// Lowest-level derivation method; all higher-level entry points funnel
    /// through this.
    ///
    /// # Errors
    ///
    /// Returns an error if derivation fails.
    pub fn derive_bip32_path(
        &self,
        path: &DerivationPath,
        address_type: AddressType,
    ) -> Result<BtcAccount, DeriveError> {
        let derived = self.master_key.derive_priv(&self.secp, path.inner())?;

        let private_key = PrivateKey::new(derived.private_key, self.network.to_bitcoin_network());
        let public_key = CompressedPublicKey::from_private_key(&self.secp, &private_key)
            .map_err(|_| DeriveError::InvalidPrivateKey)?;

        let address = create_address(&public_key, self.network, address_type);

        let sk_bytes = Zeroizing::new(derived.private_key.secret_bytes());
        let pk_bytes = public_key.to_bytes();

        let inner = DerivedAccount::new(
            path.to_string(),
            sk_bytes,
            pk_bytes.to_vec(),
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
    type Error = DeriveError;

    fn derive(&self, index: u32) -> Result<DerivedAccount, DeriveError> {
        Ok(self
            .derive_with(AddressType::P2wpkh, index)?
            .into_derived_account())
    }

    fn derive_path(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        let parsed = DerivationPath::from_path_str(path)?;
        Ok(self
            .derive_bip32_path(&parsed, AddressType::P2wpkh)?
            .into_derived_account())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_wallet() -> Wallet {
        Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap()
    }

    #[test]
    fn kat_p2wpkh() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
        let acct = deriver.derive_with(AddressType::P2wpkh, 0).unwrap();
        assert_eq!(acct.address(), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        assert_eq!(acct.path(), "m/84'/0'/0'/0/0");
        assert_eq!(acct.address_type(), AddressType::P2wpkh);
    }

    #[test]
    fn kat_p2pkh() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
        let acct = deriver.derive_with(AddressType::P2pkh, 0).unwrap();
        assert_eq!(acct.address(), "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA");
        assert_eq!(acct.path(), "m/44'/0'/0'/0/0");
    }

    #[test]
    fn kat_p2sh_p2wpkh() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
        let acct = deriver.derive_with(AddressType::P2shP2wpkh, 0).unwrap();
        assert_eq!(acct.address(), "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf");
        assert_eq!(acct.path(), "m/49'/0'/0'/0/0");
    }

    #[test]
    fn p2tr_prefix() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
        let acct = deriver.derive_with(AddressType::P2tr, 0).unwrap();
        assert!(acct.address().starts_with("bc1p"));
        assert_eq!(acct.path(), "m/86'/0'/0'/0/0");
    }

    #[test]
    fn derive_default_is_p2wpkh() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
        let def = deriver.derive(0).unwrap();
        let explicit = deriver.derive_with(AddressType::P2wpkh, 0).unwrap();
        assert_eq!(def.address(), explicit.address());
    }

    #[test]
    fn testnet_prefix() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Testnet).unwrap();
        let acct = deriver.derive(0).unwrap();
        assert!(acct.address().starts_with("tb1q"));
        assert_eq!(acct.path(), "m/84'/1'/0'/0/0");
    }

    #[test]
    fn derive_many_unique() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
        let addrs = deriver.derive_many(0, 5).unwrap();
        assert_eq!(addrs.len(), 5);
        let mut unique: Vec<&str> = addrs.iter().map(|a| a.address()).collect();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), 5);
    }

    #[test]
    fn passphrase_changes_addresses() {
        let wallet1 = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        let wallet2 = Wallet::from_mnemonic(TEST_MNEMONIC, Some("password")).unwrap();
        let d1 = Deriver::new(&wallet1, Network::Mainnet).unwrap();
        let d2 = Deriver::new(&wallet2, Network::Mainnet).unwrap();
        assert_ne!(
            d1.derive(0).unwrap().address(),
            d2.derive(0).unwrap().address()
        );
    }

    #[test]
    fn wif_is_populated() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
        let acct = deriver.derive(0).unwrap();
        assert!(!acct.private_key_wif().is_empty());
        assert_eq!(acct.private_key_bytes().len(), 32);
    }

    #[test]
    fn bytes_accessors_roundtrip() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
        let acct = deriver.derive_with(AddressType::P2wpkh, 0).unwrap();

        let sk = acct.private_key_bytes();
        assert_eq!(sk.len(), 32);

        let pk = acct.public_key_bytes();
        assert_eq!(pk.len(), 33);
        assert_eq!(hex::encode(pk), acct.public_key_hex());
    }
}
