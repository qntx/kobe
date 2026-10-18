//! Shared address encoders and secret-material formatters (crate-internal).

#[cfg(any(
    feature = "btc",
    feature = "ltc",
    feature = "doge",
    feature = "bch",
    feature = "tron",
    feature = "xrp",
))]
pub(crate) mod base58;
#[cfg(any(feature = "bch", feature = "kaspa"))]
pub(crate) mod cashaddr;
#[cfg(any(
    feature = "btc",
    feature = "ltc",
    feature = "doge",
    feature = "bch",
    feature = "evm",
    feature = "tron",
    feature = "cosmos",
    feature = "xrp",
    feature = "fil",
    feature = "casper",
    feature = "sui",
    feature = "ada",
))]
pub(crate) mod hash;
#[cfg(any(
    feature = "aptos",
    feature = "casper",
    feature = "cosmos",
    feature = "evm",
    feature = "fil",
    feature = "kaspa",
    feature = "sol",
    feature = "near",
    feature = "spark",
    feature = "ton",
    feature = "tron",
    feature = "xrp",
))]
pub(crate) mod secret;
#[cfg(any(feature = "btc", feature = "ltc", feature = "doge"))]
pub(crate) mod segwit;
#[cfg(feature = "xlm")]
pub(crate) mod strkey;

/// Filecoin lowercase base32 (RFC 4648 alphabet, no padding).
#[cfg(feature = "fil")]
pub(crate) fn base32_lower(data: &[u8]) -> alloc::string::String {
    data_encoding::BASE32_NOPAD.encode(data).to_lowercase()
}
