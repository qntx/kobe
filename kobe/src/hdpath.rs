//! BIP-32 Derivation Path support.
//!
//! Provides structured parsing and manipulation of hierarchical deterministic
//! key derivation paths like "m/44'/60'/0'/0/0".

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::error::{Error, Result};
use core::fmt;

/// A child index in a derivation path.
///
/// Can be either normal (non-hardened) or hardened.
/// Hardened indices are >= 2^31 in raw form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChildIndex {
    /// Normal (non-hardened) index: 0 to 2^31 - 1
    Normal(u32),
    /// Hardened index: displayed as n' or nh, stored as n
    Hardened(u32),
}

impl ChildIndex {
    /// The offset for hardened indices (2^31).
    pub const HARDENED_OFFSET: u32 = 0x8000_0000;

    /// Create a normal (non-hardened) child index.
    pub const fn normal(index: u32) -> Result<Self> {
        if index >= Self::HARDENED_OFFSET {
            Err(Error::InvalidDerivationPath)
        } else {
            Ok(Self::Normal(index))
        }
    }

    /// Create a hardened child index.
    pub const fn hardened(index: u32) -> Result<Self> {
        if index >= Self::HARDENED_OFFSET {
            Err(Error::InvalidDerivationPath)
        } else {
            Ok(Self::Hardened(index))
        }
    }

    /// Check if this is a hardened index.
    pub const fn is_hardened(&self) -> bool {
        matches!(self, Self::Hardened(_))
    }

    /// Check if this is a normal (non-hardened) index.
    pub const fn is_normal(&self) -> bool {
        matches!(self, Self::Normal(_))
    }

    /// Get the raw index value (without hardened flag).
    pub const fn index(&self) -> u32 {
        match self {
            Self::Normal(i) | Self::Hardened(i) => *i,
        }
    }

    /// Convert to the raw u32 value used in BIP-32 derivation.
    ///
    /// For hardened indices, this includes the hardened offset (2^31).
    pub const fn to_u32(&self) -> u32 {
        match self {
            Self::Normal(i) => *i,
            Self::Hardened(i) => *i | Self::HARDENED_OFFSET,
        }
    }
}

impl From<u32> for ChildIndex {
    fn from(value: u32) -> Self {
        if value >= Self::HARDENED_OFFSET {
            Self::Hardened(value & !Self::HARDENED_OFFSET)
        } else {
            Self::Normal(value)
        }
    }
}

impl From<ChildIndex> for u32 {
    fn from(index: ChildIndex) -> Self {
        index.to_u32()
    }
}

impl fmt::Display for ChildIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Normal(i) => write!(f, "{}", i),
            Self::Hardened(i) => write!(f, "{}'", i),
        }
    }
}

#[cfg(feature = "alloc")]
impl core::str::FromStr for ChildIndex {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();

        if s.ends_with('\'') || s.ends_with('h') || s.ends_with('H') {
            let index_str = &s[..s.len() - 1];
            let index: u32 = index_str
                .parse()
                .map_err(|_| Error::InvalidDerivationPath)?;
            Self::hardened(index)
        } else {
            let index: u32 = s.parse().map_err(|_| Error::InvalidDerivationPath)?;
            Self::normal(index)
        }
    }
}

/// A BIP-32 derivation path.
///
/// Represents paths like "m/44'/60'/0'/0/0" as a sequence of child indices.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DerivationPath {
    /// The sequence of child indices in the path.
    indices: Vec<ChildIndex>,
}

#[cfg(feature = "alloc")]
impl DerivationPath {
    /// Create an empty derivation path (master key).
    pub fn master() -> Self {
        Self {
            indices: Vec::new(),
        }
    }

    /// Create a derivation path from a vector of child indices.
    pub fn new(indices: Vec<ChildIndex>) -> Self {
        Self { indices }
    }

    /// Parse a derivation path from a string.
    ///
    /// Supports formats like:
    /// - "m/44'/60'/0'/0/0"
    /// - "m/44h/60h/0h/0/0"
    /// - "44'/60'/0'/0/0"
    pub fn parse(path: &str) -> Result<Self> {
        let path = path.trim();

        // Handle empty path or just "m"
        if path.is_empty() || path == "m" || path == "M" {
            return Ok(Self::master());
        }

        // Strip leading "m/" or "M/"
        let path = if path.starts_with("m/") || path.starts_with("M/") {
            &path[2..]
        } else {
            path
        };

        let mut indices = Vec::new();

        for component in path.split('/') {
            if component.is_empty() {
                continue;
            }

            let index: ChildIndex = component.parse()?;
            indices.push(index);
        }

        Ok(Self { indices })
    }

    /// Get the child indices in this path.
    pub fn indices(&self) -> &[ChildIndex] {
        &self.indices
    }

    /// Get the number of levels in this path.
    pub fn depth(&self) -> usize {
        self.indices.len()
    }

    /// Check if this path is empty (master key).
    pub fn is_master(&self) -> bool {
        self.indices.is_empty()
    }

    /// Check if any index in the path is hardened.
    pub fn has_hardened(&self) -> bool {
        self.indices.iter().any(ChildIndex::is_hardened)
    }

    /// Append a child index to the path.
    pub fn child(&self, index: ChildIndex) -> Self {
        let mut indices = self.indices.clone();
        indices.push(index);
        Self { indices }
    }

    /// Append a normal child index.
    pub fn normal_child(&self, index: u32) -> Result<Self> {
        Ok(self.child(ChildIndex::normal(index)?))
    }

    /// Append a hardened child index.
    pub fn hardened_child(&self, index: u32) -> Result<Self> {
        Ok(self.child(ChildIndex::hardened(index)?))
    }

    /// Get the parent path, if any.
    pub fn parent(&self) -> Option<Self> {
        if self.indices.is_empty() {
            None
        } else {
            let mut indices = self.indices.clone();
            indices.pop();
            Some(Self { indices })
        }
    }

    /// Create BIP-44 path: m/44'/coin_type'/account'/change/address_index
    pub fn bip44(coin_type: u32, account: u32, change: u32, address_index: u32) -> Result<Self> {
        Ok(Self {
            indices: vec![
                ChildIndex::hardened(44)?,
                ChildIndex::hardened(coin_type)?,
                ChildIndex::hardened(account)?,
                ChildIndex::normal(change)?,
                ChildIndex::normal(address_index)?,
            ],
        })
    }

    /// Create BIP-44 Bitcoin path: m/44'/0'/account'/change/address_index
    pub fn bip44_bitcoin(account: u32, change: u32, address_index: u32) -> Result<Self> {
        Self::bip44(0, account, change, address_index)
    }

    /// Create BIP-44 Ethereum path: m/44'/60'/account'/change/address_index
    pub fn bip44_ethereum(account: u32, change: u32, address_index: u32) -> Result<Self> {
        Self::bip44(60, account, change, address_index)
    }

    /// Create BIP-49 (SegWit) path: m/49'/coin_type'/account'/change/address_index
    pub fn bip49(coin_type: u32, account: u32, change: u32, address_index: u32) -> Result<Self> {
        Ok(Self {
            indices: vec![
                ChildIndex::hardened(49)?,
                ChildIndex::hardened(coin_type)?,
                ChildIndex::hardened(account)?,
                ChildIndex::normal(change)?,
                ChildIndex::normal(address_index)?,
            ],
        })
    }

    /// Create BIP-84 (Native SegWit) path: m/84'/coin_type'/account'/change/address_index
    pub fn bip84(coin_type: u32, account: u32, change: u32, address_index: u32) -> Result<Self> {
        Ok(Self {
            indices: vec![
                ChildIndex::hardened(84)?,
                ChildIndex::hardened(coin_type)?,
                ChildIndex::hardened(account)?,
                ChildIndex::normal(change)?,
                ChildIndex::normal(address_index)?,
            ],
        })
    }

    /// Create BIP-86 (Taproot) path: m/86'/coin_type'/account'/change/address_index
    pub fn bip86(coin_type: u32, account: u32, change: u32, address_index: u32) -> Result<Self> {
        Ok(Self {
            indices: vec![
                ChildIndex::hardened(86)?,
                ChildIndex::hardened(coin_type)?,
                ChildIndex::hardened(account)?,
                ChildIndex::normal(change)?,
                ChildIndex::normal(address_index)?,
            ],
        })
    }
}

#[cfg(feature = "alloc")]
impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "m")?;
        for index in &self.indices {
            write!(f, "/{}", index)?;
        }
        Ok(())
    }
}

#[cfg(feature = "alloc")]
impl core::str::FromStr for DerivationPath {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

#[cfg(feature = "alloc")]
impl Default for DerivationPath {
    fn default() -> Self {
        Self::master()
    }
}

#[cfg(all(feature = "alloc", test))]
mod tests {
    use super::*;

    #[test]
    fn test_child_index_normal() {
        let index = ChildIndex::normal(0).unwrap();
        assert!(index.is_normal());
        assert!(!index.is_hardened());
        assert_eq!(index.index(), 0);
        assert_eq!(index.to_u32(), 0);
        assert_eq!(index.to_string(), "0");
    }

    #[test]
    fn test_child_index_hardened() {
        let index = ChildIndex::hardened(44).unwrap();
        assert!(index.is_hardened());
        assert!(!index.is_normal());
        assert_eq!(index.index(), 44);
        assert_eq!(index.to_u32(), 44 | 0x80000000);
        assert_eq!(index.to_string(), "44'");
    }

    #[test]
    fn test_child_index_from_u32() {
        assert_eq!(ChildIndex::from(0), ChildIndex::Normal(0));
        assert_eq!(ChildIndex::from(44), ChildIndex::Normal(44));
        assert_eq!(ChildIndex::from(0x80000000), ChildIndex::Hardened(0));
        assert_eq!(ChildIndex::from(0x80000000 + 44), ChildIndex::Hardened(44));
    }

    #[test]
    fn test_child_index_parse() {
        assert_eq!("0".parse::<ChildIndex>().unwrap(), ChildIndex::Normal(0));
        assert_eq!("44".parse::<ChildIndex>().unwrap(), ChildIndex::Normal(44));
        assert_eq!(
            "44'".parse::<ChildIndex>().unwrap(),
            ChildIndex::Hardened(44)
        );
        assert_eq!(
            "44h".parse::<ChildIndex>().unwrap(),
            ChildIndex::Hardened(44)
        );
        assert_eq!(
            "44H".parse::<ChildIndex>().unwrap(),
            ChildIndex::Hardened(44)
        );
    }

    #[test]
    fn test_derivation_path_parse() {
        let path: DerivationPath = "m/44'/60'/0'/0/0".parse().unwrap();
        assert_eq!(path.depth(), 5);
        assert_eq!(path.indices()[0], ChildIndex::Hardened(44));
        assert_eq!(path.indices()[1], ChildIndex::Hardened(60));
        assert_eq!(path.indices()[2], ChildIndex::Hardened(0));
        assert_eq!(path.indices()[3], ChildIndex::Normal(0));
        assert_eq!(path.indices()[4], ChildIndex::Normal(0));
    }

    #[test]
    fn test_derivation_path_display() {
        let path: DerivationPath = "m/44'/60'/0'/0/0".parse().unwrap();
        assert_eq!(path.to_string(), "m/44'/60'/0'/0/0");
    }

    #[test]
    fn test_derivation_path_master() {
        let path = DerivationPath::master();
        assert!(path.is_master());
        assert_eq!(path.depth(), 0);
        assert_eq!(path.to_string(), "m");
    }

    #[test]
    fn test_derivation_path_child() {
        let master = DerivationPath::master();
        let child = master.hardened_child(44).unwrap();
        assert_eq!(child.depth(), 1);
        assert_eq!(child.to_string(), "m/44'");
    }

    #[test]
    fn test_derivation_path_parent() {
        let path: DerivationPath = "m/44'/60'/0'".parse().unwrap();
        let parent = path.parent().unwrap();
        assert_eq!(parent.to_string(), "m/44'/60'");
    }

    #[test]
    fn test_bip44_bitcoin() {
        let path = DerivationPath::bip44_bitcoin(0, 0, 0).unwrap();
        assert_eq!(path.to_string(), "m/44'/0'/0'/0/0");
    }

    #[test]
    fn test_bip44_ethereum() {
        let path = DerivationPath::bip44_ethereum(0, 0, 0).unwrap();
        assert_eq!(path.to_string(), "m/44'/60'/0'/0/0");
    }

    #[test]
    fn test_bip84_bitcoin() {
        let path = DerivationPath::bip84(0, 0, 0, 0).unwrap();
        assert_eq!(path.to_string(), "m/84'/0'/0'/0/0");
    }

    #[test]
    fn test_bip86_taproot() {
        let path = DerivationPath::bip86(0, 0, 0, 0).unwrap();
        assert_eq!(path.to_string(), "m/86'/0'/0'/0/0");
    }

    #[test]
    fn test_has_hardened() {
        let path1: DerivationPath = "m/0/1/2".parse().unwrap();
        assert!(!path1.has_hardened());

        let path2: DerivationPath = "m/44'/0'/0'".parse().unwrap();
        assert!(path2.has_hardened());
    }
}
