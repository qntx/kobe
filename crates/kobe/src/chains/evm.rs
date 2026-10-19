//! EVM chains (Ethereum & co): BIP-32 secp256k1, EIP-55 addresses.

use alloc::string::String;
use alloc::vec::Vec;

use sha3::{Digest as _, Keccak256};

use crate::encoding::secret::hex_secret_prefixed;
use crate::hd::bip32;
use crate::{Account, Chain, DerivationPath, Error, SecretKey, Style, Wallet};

/// The EVM chain (coin type 60, shared by all EVM-compatible networks).
#[derive(Debug, Clone, Copy, Default)]
pub struct Evm;

impl Chain for Evm {
    fn styles(&self) -> Vec<Style> {
        Vec::from([
            Style::new(
                "standard",
                "m/44'/60'/0'/0/{i}",
                "MetaMask, Rabby, Trezor Suite, OneKey, Trust Wallet",
            ),
            Style::new("ledger-live", "m/44'/60'/{i}'/0/0", "Ledger Live"),
            Style::new(
                "ledger-legacy",
                "m/44'/60'/0'/{i}",
                "Ledger Live (legacy), MyEtherWallet, MyCrypto",
            )
            .aliases(&["mew"]),
        ])
    }

    fn derive(&self, wallet: &Wallet, path: &DerivationPath) -> Result<Account, Error> {
        let node = bip32::Node::derive(wallet.seed(), path)?;
        let secret = node.private_key();
        let public_key = node.public_key_uncompressed();

        Ok(Account::new(
            path.clone(),
            to_checksum(&crate::encoding::hash::eth_address_bytes(&public_key)),
            hex::encode(public_key),
            hex_secret_prefixed("0x", secret.as_slice()),
            SecretKey::Secp256k1(secret),
        ))
    }
}

/// EIP-55 mixed-case checksum of a 20-byte address (`0x` prefixed).
fn to_checksum(address: &[u8; 20]) -> String {
    let lower = hex::encode(address);
    let hash = Keccak256::digest(lower.as_bytes());

    let (pairs, _) = lower.as_bytes().as_chunks::<2>();
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (pair, &h) in pairs.iter().zip(hash.iter()) {
        for (c, nibble) in pair.iter().zip([h >> 4, h & 0x0f]) {
            let c = char::from(*c);
            out.push(if nibble >= 8 {
                c.to_ascii_uppercase()
            } else {
                c
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(s: &str) -> [u8; 20] {
        let mut out = [0u8; 20];
        hex::decode_to_slice(s.trim_start_matches("0x"), &mut out).unwrap();
        out
    }

    /// The four official EIP-55 test vectors.
    #[test]
    fn eip55_spec_vectors() {
        for (input, expected) in [
            (
                "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
                "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            ),
            (
                "0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359",
                "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            ),
            (
                "0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb",
                "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            ),
            (
                "0xd1220a0cf47c7b9be7a2e6ba89f429762e7b9adb",
                "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
            ),
        ] {
            assert_eq!(to_checksum(&bytes(input)), expected);
        }
    }
}
