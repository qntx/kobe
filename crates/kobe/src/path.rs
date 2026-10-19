//! BIP-32 style derivation paths: `m/44'/60'/0'/0/0`.

use alloc::format;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use crate::Error;

/// One step in a [`DerivationPath`]: a child index, hardened or normal.
///
/// Opaque wrapper over the BIP-32 *wire value* (index with the hardened
/// bit applied), so the `< 2^31` index invariant holds by construction:
/// values can only be created through [`ChildIndex::normal`],
/// [`ChildIndex::hardened`], or the [`DerivationPath`] parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChildIndex(u32);

impl ChildIndex {
    /// Largest permitted index value: `2^31 - 1`.
    pub const MAX: u32 = (1 << 31) - 1;

    /// A normal (non-hardened) child index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IndexOutOfRange`] if `index > 2^31 - 1`.
    pub fn normal(index: u32) -> Result<Self, Error> {
        if index > Self::MAX {
            return Err(Error::IndexOutOfRange(u64::from(index)));
        }
        Ok(Self(index))
    }

    /// A hardened child index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IndexOutOfRange`] if `index > 2^31 - 1`.
    pub fn hardened(index: u32) -> Result<Self, Error> {
        if index > Self::MAX {
            return Err(Error::IndexOutOfRange(u64::from(index)));
        }
        Ok(Self(index | 0x8000_0000))
    }

    /// The index value, always below `2^31`.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.0 & Self::MAX
    }

    /// Whether this step is hardened.
    #[must_use]
    pub const fn is_hardened(self) -> bool {
        self.0 & 0x8000_0000 != 0
    }

    /// The BIP-32 wire value: index with the hardened bit applied.
    #[cfg(any(feature = "hd-bip32", feature = "hd-slip10", feature = "cardano"))]
    pub(crate) const fn wire(self) -> u32 {
        self.0
    }
}

impl fmt::Display for ChildIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.index())?;
        if self.is_hardened() {
            f.write_str("'")?;
        }
        Ok(())
    }
}

/// A parsed BIP-32 derivation path (`m/…`).
///
/// Parses from strings like `m/44'/60'/0'/0/0`, accepting `'` and `h`/`H` as
/// hardened markers; the canonical [`Display`](fmt::Display) form always uses
/// `'`. The bare path `m` denotes the master node.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DerivationPath(Vec<ChildIndex>);

impl DerivationPath {
    /// The child indices in order.
    #[must_use]
    pub fn as_slice(&self) -> &[ChildIndex] {
        &self.0
    }
}

impl FromStr for DerivationPath {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        let rest = trimmed
            .strip_prefix('m')
            .or_else(|| trimmed.strip_prefix('M'))
            .ok_or_else(|| Error::Path(format!("{trimmed:?} must start with 'm'")))?;

        let mut indices = Vec::new();
        if !rest.is_empty() {
            let body = rest.strip_prefix('/').ok_or_else(|| {
                Error::Path(format!("{trimmed:?}: segments must be separated by '/'"))
            })?;
            for segment in body.split('/') {
                indices.push(parse_segment(segment)?);
            }
        }
        Ok(Self(indices))
    }
}

fn parse_segment(segment: &str) -> Result<ChildIndex, Error> {
    let (digits, hardened) = segment
        .strip_suffix('\'')
        .or_else(|| segment.strip_suffix('h'))
        .or_else(|| segment.strip_suffix('H'))
        .map_or((segment, false), |d| (d, true));
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Path(format!("invalid path segment {segment:?}")));
    }
    let index = digits
        .parse::<u32>()
        .map_err(|_| Error::Path(format!("invalid path segment {segment:?}")))?;
    if hardened {
        ChildIndex::hardened(index)
    } else {
        ChildIndex::normal(index)
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("m")?;
        for index in &self.0 {
            write!(f, "/{index}")?;
        }
        Ok(())
    }
}

impl FromIterator<ChildIndex> for DerivationPath {
    fn from_iter<I: IntoIterator<Item = ChildIndex>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}
