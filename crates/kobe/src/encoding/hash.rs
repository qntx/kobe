//! Hash helpers shared by address encoders.

/// `RIPEMD-160(SHA-256(data))` — Bitcoin-style script-hash payloads.
#[cfg(any(
    feature = "btc",
    feature = "ltc",
    feature = "doge",
    feature = "bch",
    feature = "cosmos",
    feature = "xrp",
))]
pub(crate) fn hash160(data: &[u8]) -> [u8; 20] {
    use ripemd::Ripemd160;
    use sha2::{Digest, Sha256};

    let sha = Sha256::digest(data);
    Ripemd160::digest(sha).into()
}

/// `SHA-256(SHA-256(data))` — `Base58Check` checksums.
#[cfg(any(
    feature = "btc",
    feature = "ltc",
    feature = "doge",
    feature = "bch",
    feature = "tron",
    feature = "xrp",
))]
pub(crate) fn double_sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let first = Sha256::digest(data);
    Sha256::digest(first).into()
}

/// The 20-byte Ethereum-style address of a 65-byte uncompressed public key:
/// `keccak256(pubkey[1..])[12..]`.
#[cfg(any(feature = "evm", feature = "tron", feature = "cosmos"))]
pub(crate) fn eth_address_bytes(public_key: &[u8; 65]) -> [u8; 20] {
    use sha3::{Digest as _, Keccak256};

    let &[_, key @ ..] = public_key;
    let hash: [u8; 32] = Keccak256::digest(key).into();
    let [_, _, _, _, _, _, _, _, _, _, _, _, address @ ..] = hash;
    address
}

/// `BLAKE2b-160` — Filecoin address payloads.
#[cfg(feature = "fil")]
pub(crate) fn blake2b_160(data: &[u8]) -> [u8; 20] {
    use blake2::Digest;
    blake2::Blake2b::<blake2::digest::consts::U20>::digest(data).into()
}

/// `BLAKE2b-224` — Cardano key hashes.
#[cfg(feature = "ada")]
pub(crate) fn blake2b_224(data: &[u8]) -> [u8; 28] {
    use blake2::Digest;
    blake2::Blake2b::<blake2::digest::consts::U28>::digest(data).into()
}

/// `BLAKE2b-256` — Casper account hashes, Sui addresses.
#[cfg(any(feature = "casper", feature = "sui"))]
pub(crate) fn blake2b_256(data: &[u8]) -> [u8; 32] {
    use blake2::Digest;
    blake2::Blake2b256::digest(data).into()
}
