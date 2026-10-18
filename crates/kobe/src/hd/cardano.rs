//! Cardano CIP-3 master-key generation: Icarus, Ledger/BitBox02 and
//! Icarus-Trezor. Each produces a 96-byte extended private key
//! (`kL ‖ kR ‖ chain code`) consumable by `ed25519-bip32` `XPrv`.

use alloc::vec::Vec;

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use crate::{Error, Wallet};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// 96-byte extended private key material (`kL ‖ kR ‖ chain code`).
pub(crate) type XPrvBytes = Zeroizing<[u8; 96]>;

/// ED25519-BIP32 clamping on `kL` (the scalar half of the extended key).
///
/// Icarus clears bits 0-2, 5 and 7 and sets bit 6 of the last byte;
/// Ledger's `hash_repeatedly` already guarantees bit 5 is clear.
const fn tweak_bits(data: &mut [u8; 96], icarus: bool) {
    let (kl, _) = data.split_at_mut(32);
    if let Some(kl0) = kl.first_mut() {
        *kl0 &= 0b1111_1000;
    }
    if let Some(kl31) = kl.last_mut() {
        *kl31 &= if icarus { 0b0001_1111 } else { 0b0111_1111 };
        *kl31 |= 0b0100_0000;
    }
}

/// Icarus master key: `PBKDF2-HMAC-SHA512(password = passphrase,
/// salt = entropy, iter = 4096, dkLen = 96)`, then clamped.
fn icarus(entropy: &[u8], passphrase: &str) -> XPrvBytes {
    let mut out = Zeroizing::new([0u8; 96]);
    pbkdf2::pbkdf2_hmac::<Sha512>(passphrase.as_bytes(), entropy, 4096, out.as_mut_slice());
    tweak_bits(&mut out, true);
    out
}

/// Icarus-Trezor master key: identical to Icarus, except that for 24-word
/// mnemonics (256-bit entropy) Trezor's firmware bug passes the BIP-39
/// checksum byte along with the entropy as the PBKDF2 salt (CIP-3 /
/// trezor-firmware#1388): `salt = entropy ‖ sha256(entropy)[0]`.
fn icarus_trezor(entropy: &[u8], passphrase: &str) -> XPrvBytes {
    if entropy.len() != 32 {
        return icarus(entropy, passphrase);
    }
    let checksum = Sha256::digest(entropy).first().copied().unwrap_or(0);
    let mut salt = Zeroizing::new(Vec::with_capacity(33));
    salt.extend_from_slice(entropy);
    salt.push(checksum);
    let mut out = Zeroizing::new([0u8; 96]);
    pbkdf2::pbkdf2_hmac::<Sha512>(passphrase.as_bytes(), &salt, 4096, out.as_mut_slice());
    tweak_bits(&mut out, true);
    out
}

fn hmac256(key: &[u8], parts: &[&[u8]]) -> Result<[u8; 32], Error> {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key)
        .map_err(|e| Error::InvalidKey(alloc::format!("hmac: {e}")))?;
    for part in parts {
        mac.update(part);
    }
    Ok(mac.finalize().into_bytes().into())
}

fn hmac512(key: &[u8], parts: &[&[u8]]) -> Result<Zeroizing<[u8; 64]>, Error> {
    let mut mac = <HmacSha512 as KeyInit>::new_from_slice(key)
        .map_err(|e| Error::InvalidKey(alloc::format!("hmac: {e}")))?;
    for part in parts {
        mac.update(part);
    }
    Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
}

/// Ledger/BitBox02 master key from the 64-byte BIP-39 seed
/// (`seed = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" ‖ passphrase, 2048)`,
/// already computed by the wallet):
///
/// ```text
/// cc = HMAC-SHA256(key="ed25519 seed", 0x01 ‖ seed)
/// I  = HMAC-SHA512(key="ed25519 seed", seed); while iL[31] & 0x20:
///          I = HMAC-SHA512(key="ed25519 seed", iL ‖ iR)
/// master = clamp(iL) ‖ iR ‖ cc
/// ```
fn ledger(seed: &[u8; 64]) -> Result<XPrvBytes, Error> {
    let cc = hmac256(b"ed25519 seed", &[&[0x01], seed])?;
    let mut i = hmac512(b"ed25519 seed", &[seed])?;
    while i
        .as_slice()
        .first_chunk::<32>()
        .and_then(|kl| kl.last())
        .copied()
        .unwrap_or(0)
        & 0b0010_0000
        != 0
    {
        i = hmac512(b"ed25519 seed", &[i.as_slice()])?;
    }

    let mut out = Zeroizing::new([0u8; 96]);
    let (kl_kr, chain_code) = out.split_at_mut(64);
    kl_kr.copy_from_slice(i.as_slice());
    chain_code.copy_from_slice(&cc);
    tweak_bits(&mut out, false);
    Ok(out)
}

/// The CIP-3 master key for `wallet` under `master` (one of the three
/// algorithms above).
pub(crate) fn master_key(master: crate::ada::Master, wallet: &Wallet) -> Result<XPrvBytes, Error> {
    match master {
        crate::ada::Master::Icarus => Ok(icarus(wallet.entropy(), wallet.passphrase())),
        crate::ada::Master::IcarusTrezor => {
            Ok(icarus_trezor(wallet.entropy(), wallet.passphrase()))
        }
        crate::ada::Master::Ledger => ledger(wallet.seed()),
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use ed25519_bip32::{DerivationScheme, XPrv};
    use serde_json::Value;

    use super::*;
    use crate::ada::Master;

    const VECTORS: &str = include_str!("../../../../vectors/cip3.json");

    /// Official CIP-3 master-key vectors (Icarus, Ledger/BitBox02) and the
    /// trezor-firmware Icarus/Icarus-Trezor vectors (master secret for the
    /// 12-word case; derived node fields for the 24-word quirk case).
    #[test]
    fn cip3_official_vectors() {
        let file: Value = serde_json::from_str(VECTORS).unwrap();
        for case in file.get("cases").and_then(Value::as_array).unwrap() {
            let mnemonic = case.get("mnemonic").and_then(Value::as_str).unwrap();
            let passphrase = case.get("passphrase").and_then(Value::as_str).unwrap();
            let master =
                Master::from_str(case.get("master").and_then(Value::as_str).unwrap()).unwrap();
            let wallet = Wallet::from_mnemonic(mnemonic, passphrase).unwrap();
            let xprv = master_key(master, &wallet).unwrap();

            if let Some(expected) = case.get("xprv").and_then(Value::as_str) {
                assert_eq!(
                    hex::encode(xprv.as_slice()),
                    expected,
                    "master key for {mnemonic:?} ({master})"
                );
                continue;
            }

            // Derived-node vector: assert chain code, extended secret and
            // public key after the recorded wire indices.
            let mut node = XPrv::from_bytes_verified(*xprv).unwrap();
            for index in case.get("derive").and_then(Value::as_array).unwrap() {
                node = node.derive(
                    DerivationScheme::V2,
                    u32::try_from(index.as_u64().unwrap()).unwrap(),
                );
            }
            let ext = node.extended_secret_key_bytes();
            assert_eq!(
                hex::encode(&ext[..32]),
                case.get("private_key").and_then(Value::as_str).unwrap(),
                "derived scalar"
            );
            assert_eq!(
                hex::encode(&ext[32..]),
                case.get("extension").and_then(Value::as_str).unwrap(),
                "derived extension"
            );
            assert_eq!(
                hex::encode(node.chain_code()),
                case.get("chain_code").and_then(Value::as_str).unwrap(),
                "derived chain code"
            );
            assert_eq!(
                hex::encode(node.public().public_key()),
                case.get("public_key").and_then(Value::as_str).unwrap(),
                "derived public key"
            );
        }
    }
}
