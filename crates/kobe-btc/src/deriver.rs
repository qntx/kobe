//! Bitcoin address derivation from a unified wallet.

#[cfg(feature = "alloc")]
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::ops::Deref;

use kobe_primitives::{
    Derive, DeriveError, DerivedAccount, DerivedPublicKey, Wallet, derive_range,
};
use zeroize::Zeroizing;

use crate::address::create_address;
use crate::wif::encode_wif;
use crate::{AddressType, DerivationPath, Network};

/// Bitcoin address deriver from a unified wallet seed.
#[derive(Debug)]
pub struct Deriver<'a> {
    wallet: &'a Wallet,
    network: Network,
}

/// Bitcoin-specific derived account: unified [`DerivedAccount`] plus WIF,
/// address type, and structured path.
#[derive(Debug, Clone)]
pub struct BtcAccount {
    inner: DerivedAccount,
    private_key_wif: Zeroizing<String>,
    address_type: AddressType,
    bip32_path: DerivationPath,
}

impl BtcAccount {
    /// Private key in WIF, zeroized on drop.
    #[inline]
    #[must_use]
    pub const fn private_key_wif(&self) -> &Zeroizing<String> {
        &self.private_key_wif
    }

    /// Address type used for this account.
    #[inline]
    #[must_use]
    pub const fn address_type(&self) -> AddressType {
        self.address_type
    }

    /// Structured BIP-32 path.
    #[inline]
    #[must_use]
    pub const fn bip32_path(&self) -> &DerivationPath {
        &self.bip32_path
    }

    /// Borrow the unified account.
    #[inline]
    #[must_use]
    pub const fn as_derived_account(&self) -> &DerivedAccount {
        &self.inner
    }

    /// Consume into the unified account.
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

impl AsRef<DerivedAccount> for BtcAccount {
    #[inline]
    fn as_ref(&self) -> &DerivedAccount {
        &self.inner
    }
}

impl<'a> Deriver<'a> {
    /// Create a deriver. Key material is not derived until a `derive_*` call.
    ///
    /// Infallible, matching other chain crates (`Deriver::new(wallet)`).
    #[inline]
    #[must_use]
    pub const fn new(wallet: &'a Wallet, network: Network) -> Self {
        Self { wallet, network }
    }

    /// Default: P2WPKH at BIP-84.
    ///
    /// # Errors
    ///
    /// Returns an error if path, key, address, or WIF derivation fails.
    #[inline]
    pub fn derive(&self, index: u32) -> Result<BtcAccount, DeriveError> {
        self.derive_with(AddressType::P2wpkh, index)
    }

    /// Derive with an explicit address type (standard purpose path).
    ///
    /// # Errors
    ///
    /// Returns an error if path, key, address, or WIF derivation fails.
    #[inline]
    pub fn derive_with(
        &self,
        address_type: AddressType,
        index: u32,
    ) -> Result<BtcAccount, DeriveError> {
        let path = DerivationPath::bip_standard(address_type, self.network, 0, false, index)?;
        self.derive_structured(&path, address_type)
    }

    /// Derive a contiguous index range.
    ///
    /// # Errors
    ///
    /// Returns an error if the range is invalid or any account derivation fails.
    pub fn derive_many_with(
        &self,
        address_type: AddressType,
        start: u32,
        count: u32,
    ) -> Result<Vec<BtcAccount>, DeriveError> {
        derive_range(start, count, |i| self.derive_with(address_type, i))
    }

    /// Derive at a path string; infer [`AddressType`] from purpose.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is invalid or account derivation fails.
    pub fn derive_at(&self, path: &str) -> Result<BtcAccount, DeriveError> {
        let parsed = DerivationPath::from_path_str(path)?;
        let address_type = infer_address_type(&parsed).ok_or_else(|| {
            DeriveError::Path(alloc::format!(
                "btc: cannot infer address type from path '{path}'; \
                 purpose must be 44'/49'/84'/86'. \
                 Use Deriver::derive_at_with(path, address_type) for custom paths."
            ))
        })?;
        self.derive_structured(&parsed, address_type)
    }

    /// Derive at a path with an explicit address type (non-standard paths).
    ///
    /// # Errors
    ///
    /// Returns an error if the path is invalid or account derivation fails.
    pub fn derive_at_with(
        &self,
        path: &str,
        address_type: AddressType,
    ) -> Result<BtcAccount, DeriveError> {
        let parsed = DerivationPath::from_path_str(path)?;
        self.derive_structured(&parsed, address_type)
    }

    /// Low-level entry: pre-parsed path + address type.
    ///
    /// # Errors
    ///
    /// Returns an error if key, address, or WIF derivation fails.
    pub fn derive_structured(
        &self,
        path: &DerivationPath,
        address_type: AddressType,
    ) -> Result<BtcAccount, DeriveError> {
        let path_string = path.to_string();
        let derived = self.wallet.derive_secp256k1(&path_string)?;

        // Secrets remain Zeroizing end-to-end.
        let sk = derived.private_key_bytes();
        let pk = derived.compressed_pubkey();

        let address = create_address(&pk, self.network, address_type)?;
        let private_key_wif = encode_wif(&sk, self.network)?;

        let inner = DerivedAccount::new(
            path_string,
            sk,
            DerivedPublicKey::Secp256k1Compressed(pk),
            address,
        );

        Ok(BtcAccount {
            inner,
            private_key_wif,
            address_type,
            bip32_path: path.clone(),
        })
    }

    /// Network this deriver was created with.
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

    fn derive_path(&self, path: &str) -> Result<BtcAccount, DeriveError> {
        self.derive_at(path)
    }
}

fn infer_address_type(path: &DerivationPath) -> Option<AddressType> {
    let first = path.first_segment()?;
    if first.is_hardened() {
        AddressType::from_purpose(first.index())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use kobe_primitives::DeriveExt;

    use super::*;
    use crate::wif::decode_wif;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_wallet() -> Wallet {
        Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap()
    }

    fn deriver(wallet: &Wallet, network: Network) -> Deriver<'_> {
        Deriver::new(wallet, network)
    }

    #[test]
    fn derived_key_bytes_match_bip84_vector() {
        let wallet = test_wallet();
        let d = deriver(&wallet, Network::Mainnet);
        let account = d.derive_at("m/84'/0'/0'/0/0").unwrap();
        assert_eq!(
            account.private_key_hex().as_str(),
            "4604b4b710fe91f584fff084e1a9159fe4f8408fff380596a604948474ce4fa3"
        );
        assert_eq!(
            account.public_key_hex(),
            "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"
        );
    }

    #[test]
    fn kat_bip84_p2wpkh_abandon_index0() {
        let wallet = test_wallet();
        let a = deriver(&wallet, Network::Mainnet)
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
        let wallet = test_wallet();
        let a = deriver(&wallet, Network::Mainnet)
            .derive_with(AddressType::P2wpkh, 1)
            .unwrap();
        assert_eq!(a.path(), "m/84'/0'/0'/0/1");
        assert_eq!(a.address(), "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g");
    }

    #[test]
    fn kat_bip44_p2pkh_abandon_index0() {
        let wallet = test_wallet();
        let a = deriver(&wallet, Network::Mainnet)
            .derive_with(AddressType::P2pkh, 0)
            .unwrap();
        assert_eq!(a.path(), "m/44'/0'/0'/0/0");
        assert_eq!(a.address(), "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA");
    }

    #[test]
    fn kat_bip49_p2sh_p2wpkh_abandon_index0() {
        let wallet = test_wallet();
        let a = deriver(&wallet, Network::Mainnet)
            .derive_with(AddressType::P2shP2wpkh, 0)
            .unwrap();
        assert_eq!(a.path(), "m/49'/0'/0'/0/0");
        assert_eq!(a.address(), "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf");
    }

    #[test]
    fn kat_bip86_p2tr_abandon_index0() {
        let wallet = test_wallet();
        let a = deriver(&wallet, Network::Mainnet)
            .derive_with(AddressType::P2tr, 0)
            .unwrap();
        assert_eq!(a.path(), "m/86'/0'/0'/0/0");
        assert_eq!(
            a.address(),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
    }

    /// BIP-86 mainnet vector index 1:
    /// <https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki>
    #[test]
    fn kat_bip86_p2tr_abandon_index1() {
        let wallet = test_wallet();
        let a = deriver(&wallet, Network::Mainnet)
            .derive_with(AddressType::P2tr, 1)
            .unwrap();
        assert_eq!(a.path(), "m/86'/0'/0'/0/1");
        assert_eq!(
            a.address(),
            "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"
        );
    }

    #[test]
    fn kat_testnet_p2pkh_abandon_index0() {
        let wallet = test_wallet();
        let a = deriver(&wallet, Network::Testnet)
            .derive_with(AddressType::P2pkh, 0)
            .unwrap();
        assert_eq!(a.path(), "m/44'/1'/0'/0/0");
        assert_eq!(a.address(), "mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV");
    }

    /// BIP-49 testnet vector:
    /// <https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki>
    #[test]
    fn kat_testnet_p2sh_p2wpkh_abandon_index0() {
        let wallet = test_wallet();
        let a = deriver(&wallet, Network::Testnet)
            .derive_with(AddressType::P2shP2wpkh, 0)
            .unwrap();
        assert_eq!(a.path(), "m/49'/1'/0'/0/0");
        assert_eq!(a.address(), "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2");
    }

    #[test]
    fn kat_testnet_p2wpkh_abandon_index0() {
        let wallet = test_wallet();
        let a = deriver(&wallet, Network::Testnet)
            .derive_with(AddressType::P2wpkh, 0)
            .unwrap();
        assert_eq!(a.path(), "m/84'/1'/0'/0/0");
        assert_eq!(a.address(), "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl");
    }

    #[test]
    fn kat_testnet_p2tr_abandon_index0() {
        let wallet = test_wallet();
        let a = deriver(&wallet, Network::Testnet)
            .derive_with(AddressType::P2tr, 0)
            .unwrap();
        assert_eq!(a.path(), "m/86'/1'/0'/0/0");
        assert_eq!(
            a.address(),
            "tb1p8wpt9v4frpf3tkn0srd97pksgsxc5hs52lafxwru9kgeephvs7rqlqt9zj"
        );
    }

    #[test]
    fn default_derive_uses_bip84_p2wpkh() {
        let wallet = test_wallet();
        let d = deriver(&wallet, Network::Mainnet);
        let def = d.derive(0).unwrap();
        let explicit = d.derive_with(AddressType::P2wpkh, 0).unwrap();
        assert_eq!(def.address(), explicit.address());
        assert_eq!(def.path(), explicit.path());
    }

    #[test]
    fn derive_many_matches_individual() {
        let wallet = test_wallet();
        let d = deriver(&wallet, Network::Mainnet);
        let batch = d.derive_many(0, 5).unwrap();
        let single: Vec<_> = (0..5)
            .map(|i| d.derive_with(AddressType::P2wpkh, i).unwrap())
            .collect();
        for (b, s) in batch.iter().zip(single.iter()) {
            assert_eq!(b.address(), s.address());
            assert_eq!(b.path(), s.path());
        }
    }

    #[test]
    fn wif_roundtrips_to_private_key_bytes() {
        let wallet = test_wallet();
        let a = deriver(&wallet, Network::Mainnet).derive(0).unwrap();
        let (key, network) = decode_wif(a.private_key_wif().as_str()).unwrap();
        assert_eq!(key.as_ref(), a.private_key_bytes().as_ref());
        assert_eq!(network, Network::Mainnet);
    }

    #[test]
    fn wif_roundtrips_testnet_private_key_bytes() {
        let wallet = test_wallet();
        let a = deriver(&wallet, Network::Testnet).derive(0).unwrap();
        let (key, network) = decode_wif(a.private_key_wif().as_str()).unwrap();
        assert_eq!(key.as_ref(), a.private_key_bytes().as_ref());
        assert_eq!(network, Network::Testnet);
    }

    #[test]
    fn passphrase_changes_derivation() {
        let wallet = test_wallet();
        let with_pass = Wallet::from_mnemonic(TEST_MNEMONIC, Some("TREZOR")).unwrap();
        assert_ne!(
            deriver(&wallet, Network::Mainnet)
                .derive(0)
                .unwrap()
                .address(),
            deriver(&with_pass, Network::Mainnet)
                .derive(0)
                .unwrap()
                .address(),
        );
    }

    #[test]
    fn derive_path_infers_address_type_from_purpose() {
        let wallet = test_wallet();
        let d = deriver(&wallet, Network::Mainnet);

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

    #[test]
    fn derive_path_rejects_non_standard_purpose() {
        let wallet = test_wallet();
        let d = deriver(&wallet, Network::Mainnet);

        let err = d.derive_path("m/1'/2'/3'").unwrap_err();
        assert!(matches!(err, DeriveError::Path(_)));
        if let DeriveError::Path(msg) = &err {
            assert!(msg.contains("cannot infer address type"));
            assert!(msg.contains("derive_at_with"));
        }

        let non_hardened_err = d.derive_path("m/44/0'/0'/0/0").unwrap_err();
        assert!(matches!(non_hardened_err, DeriveError::Path(_)));
    }

    #[test]
    fn derive_at_matches_trait_derive_path() {
        let wallet = test_wallet();
        let d = deriver(&wallet, Network::Mainnet);
        for path in [
            "m/44'/0'/0'/0/0",
            "m/49'/0'/0'/0/0",
            "m/84'/0'/0'/0/0",
            "m/86'/0'/0'/0/0",
        ] {
            let a = d.derive_path(path).unwrap();
            let b = d.derive_at(path).unwrap();
            assert_eq!(a.address(), b.address());
            assert_eq!(a.address_type(), b.address_type());
        }
    }

    #[test]
    fn derive_at_with_accepts_non_standard_purpose() {
        let wallet = test_wallet();
        let d = deriver(&wallet, Network::Mainnet);

        let acct = d
            .derive_at_with("m/7'/0'/0'/0/0", AddressType::P2wpkh)
            .unwrap();
        assert_eq!(acct.path(), "m/7'/0'/0'/0/0");
        assert_eq!(acct.address_type(), AddressType::P2wpkh);
        assert!(acct.address().starts_with("bc1q"));

        let override_acct = d
            .derive_at_with("m/84'/0'/0'/0/0", AddressType::P2tr)
            .unwrap();
        assert_eq!(override_acct.address_type(), AddressType::P2tr);
        assert!(override_acct.address().starts_with("bc1p"));
    }

    #[test]
    fn derive_structured_matches_derive_at_with() {
        let wallet = test_wallet();
        let d = deriver(&wallet, Network::Mainnet);
        let path_str = "m/84'/0'/0'/0/0";
        let parsed = DerivationPath::from_path_str(path_str).unwrap();
        let a = d.derive_structured(&parsed, AddressType::P2wpkh).unwrap();
        let b = d.derive_at_with(path_str, AddressType::P2wpkh).unwrap();
        assert_eq!(a.address(), b.address());
        assert_eq!(a.path(), b.path());
    }
}
