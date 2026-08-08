//! Common types for Bitcoin wallet operations.

#[cfg(feature = "alloc")]
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use core::str::FromStr;

#[cfg(feature = "alloc")]
use kobe_primitives::DeriveError;

#[cfg(feature = "alloc")]
use crate::Network;

/// Bitcoin address types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum AddressType {
    /// Pay to Public Key Hash (Legacy) — `1…` / `m…`/`n…`
    P2pkh,
    /// Pay to Script Hash wrapping P2WPKH (Nested `SegWit`) — `3…` / `2…`
    P2shP2wpkh,
    /// Pay to Witness Public Key Hash (Native `SegWit`) — `bc1q…` / `tb1q…`
    #[default]
    P2wpkh,
    /// Pay to Taproot — `bc1p…` / `tb1p…`
    P2tr,
}

impl AddressType {
    /// BIP purpose for this address type.
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

    /// Inverse of [`AddressType::purpose`].
    #[inline]
    #[must_use]
    pub const fn from_purpose(purpose: u32) -> Option<Self> {
        match purpose {
            44 => Some(Self::P2pkh),
            49 => Some(Self::P2shP2wpkh),
            84 => Some(Self::P2wpkh),
            86 => Some(Self::P2tr),
            _ => None,
        }
    }

    /// Human-readable name.
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
        f.write_str(self.name())
    }
}

/// Error returned when parsing an invalid address type string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParseAddressTypeError;

impl fmt::Display for ParseAddressTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid address type, expected: p2pkh, p2sh, p2wpkh, or p2tr")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseAddressTypeError {}

impl FromStr for AddressType {
    type Err = ParseAddressTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "p2pkh" | "legacy" => Ok(Self::P2pkh),
            "p2sh" | "p2sh-p2wpkh" | "segwit" | "nested-segwit" => Ok(Self::P2shP2wpkh),
            "p2wpkh" | "native-segwit" | "bech32" => Ok(Self::P2wpkh),
            "p2tr" | "taproot" | "bech32m" => Ok(Self::P2tr),
            _ => Err(ParseAddressTypeError),
        }
    }
}

/// One BIP-32 child index (hardened or normal).
///
/// Encapsulated so callers never depend on a third-party path type.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathSegment {
    index: u32,
    hardened: bool,
}

#[cfg(feature = "alloc")]
impl PathSegment {
    /// Child index without the hardened high bit (always `< 2^31`).
    #[inline]
    #[must_use]
    pub const fn index(self) -> u32 {
        self.index
    }

    /// Whether this segment is hardened (`'` / `h`).
    #[inline]
    #[must_use]
    pub const fn is_hardened(self) -> bool {
        self.hardened
    }
}

#[cfg(feature = "alloc")]
impl fmt::Display for PathSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.index)?;
        if self.hardened {
            f.write_str("'")?;
        }
        Ok(())
    }
}

/// BIP-32 derivation path with a stable `m/…` string form.
///
/// Validated and stored independently of any third-party BIP-32 crate so the
/// public API does not leak `bip32::DerivationPath`.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationPath {
    /// Canonical `m/…` form using `'` for hardened segments.
    path: String,
    segments: Vec<PathSegment>,
}

#[cfg(feature = "alloc")]
impl DerivationPath {
    /// Standard path: `m/purpose'/coin_type'/account'/change/index`.
    ///
    /// # Errors
    ///
    /// Returns [`DeriveError::Path`] if the generated path is invalid.
    pub fn bip_standard(
        address_type: AddressType,
        network: Network,
        account: u32,
        change: bool,
        address_index: u32,
    ) -> Result<Self, DeriveError> {
        let purpose = address_type.purpose();
        let coin_type = network.coin_type();
        let change_val = u32::from(change);
        let path_str = format!("m/{purpose}'/{coin_type}'/{account}'/{change_val}/{address_index}");
        Self::from_path_str(&path_str)
    }

    /// Parse a BIP-32 path string.
    ///
    /// Accepts hardened markers `'` or `h` / `H`. The display form always uses
    /// `'`.
    ///
    /// # Errors
    ///
    /// - Empty / master-only path → [`DeriveError::Path`]
    /// - Malformed path → [`DeriveError::Path`]
    pub fn from_path_str(path: &str) -> Result<Self, DeriveError> {
        let trimmed = path.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("m") {
            return Err(DeriveError::Path(
                "btc: derivation path must contain at least one segment".into(),
            ));
        }

        let rest = trimmed
            .strip_prefix('m')
            .or_else(|| trimmed.strip_prefix('M'))
            .ok_or_else(|| DeriveError::Path("btc: derivation path must start with 'm'".into()))?;

        if rest.is_empty() {
            return Err(DeriveError::Path(
                "btc: derivation path must contain at least one segment".into(),
            ));
        }
        if !rest.starts_with('/') {
            return Err(DeriveError::Path(
                "btc: derivation path segments must be separated by '/'".into(),
            ));
        }

        let mut segments = Vec::new();
        for raw in rest[1..].split('/') {
            if raw.is_empty() {
                return Err(DeriveError::Path(
                    "btc: empty derivation path segment".into(),
                ));
            }
            let (num_part, hardened) = raw
                .strip_suffix('\'')
                .map(|n| (n, true))
                .or_else(|| raw.strip_suffix(['h', 'H']).map(|n| (n, true)))
                .unwrap_or((raw, false));
            if num_part.is_empty() || !num_part.bytes().all(|b| b.is_ascii_digit()) {
                return Err(DeriveError::Path(format!(
                    "btc: invalid derivation path segment '{raw}'"
                )));
            }
            let index: u32 = num_part.parse().map_err(|_| {
                DeriveError::Path(format!("btc: invalid derivation path index '{num_part}'"))
            })?;
            // BIP-32 child index occupies 31 bits; the high bit is the hardened flag.
            if index >= (1u32 << 31) {
                return Err(DeriveError::Path(format!(
                    "btc: derivation path index out of range: {index}"
                )));
            }
            segments.push(PathSegment { index, hardened });
        }

        if segments.is_empty() {
            return Err(DeriveError::Path(
                "btc: derivation path must contain at least one segment".into(),
            ));
        }

        let mut canonical = String::from("m");
        for seg in &segments {
            canonical.push('/');
            canonical.push_str(&seg.to_string());
        }

        Ok(Self {
            path: canonical,
            segments,
        })
    }

    /// Canonical `m/…` string (hardened as `'`).
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.path
    }

    /// Borrow the path segments.
    #[inline]
    #[must_use]
    pub fn segments(&self) -> &[PathSegment] {
        &self.segments
    }

    /// First segment, if any (used to infer BIP purpose).
    #[inline]
    #[must_use]
    pub fn first_segment(&self) -> Option<PathSegment> {
        self.segments.first().copied()
    }
}

#[cfg(feature = "alloc")]
impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.path)
    }
}

#[cfg(feature = "alloc")]
impl AsRef<str> for DerivationPath {
    fn as_ref(&self) -> &str {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_type_from_str() {
        assert_eq!("p2pkh".parse::<AddressType>().unwrap(), AddressType::P2pkh);
        assert_eq!("legacy".parse::<AddressType>().unwrap(), AddressType::P2pkh);
        assert_eq!(
            "p2sh".parse::<AddressType>().unwrap(),
            AddressType::P2shP2wpkh
        );
        assert_eq!(
            "p2wpkh".parse::<AddressType>().unwrap(),
            AddressType::P2wpkh
        );
        assert_eq!("p2tr".parse::<AddressType>().unwrap(), AddressType::P2tr);
        assert_eq!("taproot".parse::<AddressType>().unwrap(), AddressType::P2tr);
    }

    #[test]
    fn address_type_purpose() {
        assert_eq!(AddressType::P2pkh.purpose(), 44);
        assert_eq!(AddressType::P2shP2wpkh.purpose(), 49);
        assert_eq!(AddressType::P2wpkh.purpose(), 84);
        assert_eq!(AddressType::P2tr.purpose(), 86);
    }

    #[test]
    fn address_type_default() {
        assert_eq!(AddressType::default(), AddressType::P2wpkh);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn derivation_path_display_keeps_master_prefix_and_tick() {
        let path = DerivationPath::from_path_str("m/84'/0'/0'/0/0").unwrap();
        assert_eq!(path.to_string(), "m/84'/0'/0'/0/0");
        assert!(path.to_string().starts_with("m/"));
        assert!(path.to_string().contains("84'"));
        assert!(!path.to_string().contains("84h"));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn derivation_path_normalizes_h_suffix() {
        let path = DerivationPath::from_path_str("m/84h/0h/0h/0/0").unwrap();
        assert_eq!(path.to_string(), "m/84'/0'/0'/0/0");
        assert_eq!(path.as_str(), "m/84'/0'/0'/0/0");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn derivation_path_rejects_empty_forms() {
        for bad in ["", "m", "M", "  m  ", " m", "x/0", "m//0", "m/foo"] {
            assert!(
                matches!(
                    DerivationPath::from_path_str(bad),
                    Err(DeriveError::Path(_))
                ),
                "expected Path error for {bad:?}"
            );
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn first_segment_reports_hardened_purpose() {
        let path = DerivationPath::from_path_str("m/84'/0'/0'/0/0").unwrap();
        let first = path.first_segment().unwrap();
        assert!(first.is_hardened());
        assert_eq!(first.index(), 84);
    }
}
