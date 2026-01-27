//! Common types for Bitcoin wallet operations.

#[cfg(feature = "alloc")]
use alloc::{format, string::ToString};

#[cfg(feature = "alloc")]
use crate::{Error, Network};
use core::fmt;
#[cfg(feature = "alloc")]
use core::str::FromStr;

/// Bitcoin address types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddressType {
    /// Pay to Public Key Hash (Legacy) - starts with 1 or m/n
    P2pkh,
    /// Pay to Script Hash wrapping P2WPKH (SegWit compatible) - starts with 3 or 2
    P2shP2wpkh,
    /// Pay to Witness Public Key Hash (Native SegWit) - starts with bc1q or tb1q
    #[default]
    P2wpkh,
    /// Pay to Taproot (Taproot/SegWit v1) - starts with bc1p or tb1p
    P2tr,
}

impl AddressType {
    /// Get the BIP purpose for this address type.
    #[inline]
    #[must_use]
    pub const fn purpose(self) -> u32 {
        match self {
            Self::P2pkh => 44,
            Self::P2shP2wpkh => 49,
            Self::P2wpkh => 84,
            Self::P2tr => 86,
        }
    }

    /// Get address type name.
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::P2pkh => "P2PKH (Legacy)",
            Self::P2shP2wpkh => "P2SH-P2WPKH (SegWit)",
            Self::P2wpkh => "P2WPKH (Native SegWit)",
            Self::P2tr => "P2TR (Taproot)",
        }
    }
}

impl fmt::Display for AddressType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// BIP32 derivation path.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationPath {
    inner: bitcoin::bip32::DerivationPath,
}

#[cfg(feature = "alloc")]
impl DerivationPath {
    /// Create a BIP44/49/84 standard path.
    ///
    /// Format: `m/purpose'/coin_type'/account'/change/address_index`
    #[must_use]
    pub fn bip_standard(
        address_type: AddressType,
        network: Network,
        account: u32,
        change: bool,
        address_index: u32,
    ) -> Self {
        let purpose = address_type.purpose();
        let coin_type = network.coin_type();
        let change_val = if change { 1 } else { 0 };

        let path_str = format!("m/{purpose}'/{coin_type}'/{account}'/{change_val}/{address_index}");

        Self {
            inner: path_str.parse().expect("valid BIP standard path"),
        }
    }

    /// Create from a custom path string.
    ///
    /// # Errors
    ///
    /// Returns an error if the path string is invalid.
    pub fn from_path_str(path: &str) -> Result<Self, Error> {
        let inner = bitcoin::bip32::DerivationPath::from_str(path)
            .map_err(|e| Error::InvalidDerivationPath(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Get the inner bitcoin derivation path.
    #[inline]
    #[must_use]
    pub fn inner(&self) -> &bitcoin::bip32::DerivationPath {
        &self.inner
    }
}

#[cfg(feature = "alloc")]
impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "m/{}", self.inner)
    }
}

#[cfg(feature = "alloc")]
impl AsRef<bitcoin::bip32::DerivationPath> for DerivationPath {
    fn as_ref(&self) -> &bitcoin::bip32::DerivationPath {
        &self.inner
    }
}
