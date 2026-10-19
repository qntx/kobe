//! Shared address encoders and secret-material formatters (crate-internal).

#[cfg(any(
    feature = "bitcoin",
    feature = "litecoin",
    feature = "dogecoin",
    feature = "bitcoin-cash",
    feature = "tron",
    feature = "xrpl",
))]
pub(crate) mod base58;
#[cfg(any(feature = "bitcoin-cash", feature = "kaspa"))]
pub(crate) mod cashaddr;
#[cfg(any(
    feature = "bitcoin",
    feature = "litecoin",
    feature = "dogecoin",
    feature = "bitcoin-cash",
    feature = "evm",
    feature = "tron",
    feature = "cosmos",
    feature = "xrpl",
    feature = "filecoin",
    feature = "casper",
    feature = "sui",
    feature = "cardano",
))]
pub(crate) mod hash;
#[cfg(any(
    feature = "aptos",
    feature = "casper",
    feature = "cosmos",
    feature = "evm",
    feature = "filecoin",
    feature = "kaspa",
    feature = "solana",
    feature = "near",
    feature = "spark",
    feature = "ton",
    feature = "tron",
    feature = "xrpl",
))]
pub(crate) mod secret;
#[cfg(any(feature = "bitcoin", feature = "litecoin", feature = "dogecoin"))]
pub(crate) mod segwit;
#[cfg(feature = "stellar")]
pub(crate) mod strkey;
#[cfg(any(feature = "bitcoin", feature = "kaspa"))]
pub(crate) mod taproot;

/// Filecoin lowercase base32 (RFC 4648 alphabet, no padding).
#[cfg(feature = "filecoin")]
pub(crate) fn base32_lower(data: &[u8]) -> alloc::string::String {
    data_encoding::BASE32_NOPAD.encode(data).to_lowercase()
}
