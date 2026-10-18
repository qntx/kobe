//! Bitcoin (BTC): BIP-32/44/49/84/86 derivation and address encoding.
//!
//! P2PKH/P2SH-P2WPKH are `Base58Check`, P2WPKH is segwit-v0 bech32, and P2TR is
//! BIP-86 key-path-only taproot (bech32m). The private key is compressed WIF.
//! Only key-path P2TR is supported: no script trees and no signing.
//!
//! ```
//! use kobe::btc::{Bitcoin, Kind, Network};
//! use kobe::{Chain, Wallet};
//!
//! let wallet = Wallet::from_mnemonic(
//!     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
//!     "",
//! )?;
//! let btc = Bitcoin::new(Network::Mainnet, Kind::P2wpkh);
//! let account = btc.derive(&wallet, &btc.styles()[0].path(0)?)?;
//! assert_eq!(account.address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
//! # Ok::<(), kobe::Error>(())
//! ```

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::hd::bip32;
use crate::{Account, Chain, DerivationPath, Error, SecretKey, Style, Wallet, encoding};

crate::option_enum! {
    /// Bitcoin network selection.
    pub enum Network {
        /// Bitcoin mainnet (`bc`, coin type 0).
        #[default]
        Mainnet = "mainnet",
        /// Bitcoin testnet (`tb`, coin type 1).
        Testnet = "testnet",
        /// Bitcoin regtest (`bcrt`, coin type 1).
        Regtest = "regtest",
    }
}

impl Network {
    /// BIP-44 coin type: 0 on mainnet, 1 on testnet and regtest.
    #[must_use]
    pub const fn coin_type(self) -> u32 {
        match self {
            Self::Mainnet => 0,
            Self::Testnet | Self::Regtest => 1,
        }
    }

    const fn hrp(self) -> bech32::Hrp {
        match self {
            Self::Mainnet => bech32::hrp::BC,
            Self::Testnet => bech32::hrp::TB,
            Self::Regtest => bech32::hrp::BCRT,
        }
    }

    const fn p2pkh_version(self) -> u8 {
        match self {
            Self::Mainnet => 0x00,
            Self::Testnet | Self::Regtest => 0x6f,
        }
    }

    const fn p2sh_version(self) -> u8 {
        match self {
            Self::Mainnet => 0x05,
            Self::Testnet | Self::Regtest => 0xc4,
        }
    }

    const fn wif_version(self) -> u8 {
        match self {
            Self::Mainnet => 0x80,
            Self::Testnet | Self::Regtest => 0xef,
        }
    }
}

crate::option_enum! {
    /// Bitcoin address kind (output type).
    pub enum Kind {
        /// Legacy pay-to-public-key-hash (`1…` / `m…`/`n…`).
        P2pkh = "p2pkh",
        /// Segwit wrapped in P2SH (`3…` / `2…`).
        P2shP2wpkh = "p2sh-p2wpkh",
        /// Native segwit v0 pay-to-witness-public-key-hash (`bc1q…` / `tb1q…`).
        #[default]
        P2wpkh = "p2wpkh",
        /// Taproot key-path-only output (`bc1p…` / `tb1p…` / `bcrt1p…`).
        P2tr = "p2tr",
    }
}

impl Kind {
    /// BIP purpose: 44/49/84/86.
    #[must_use]
    pub const fn purpose(self) -> u32 {
        match self {
            Self::P2pkh => 44,
            Self::P2shP2wpkh => 49,
            Self::P2wpkh => 84,
            Self::P2tr => 86,
        }
    }
}

/// The Bitcoin chain.
#[derive(Debug, Clone, Copy, Default)]
pub struct Bitcoin {
    /// Target network.
    pub network: Network,
    /// Address kind.
    pub kind: Kind,
}

impl Bitcoin {
    /// A `Bitcoin` chain for `network` and `kind`.
    #[must_use]
    pub const fn new(network: Network, kind: Kind) -> Self {
        Self { network, kind }
    }
}

impl Chain for Bitcoin {
    fn styles(&self) -> Vec<Style> {
        let purpose = self.kind.purpose();
        let coin = self.network.coin_type();
        Vec::from([
            Style::new(
                "standard",
                format!("m/{purpose}'/{coin}'/0'/0/{{i}}"),
                "Sparrow, Electrum, Bitcoin Core, BlueWallet",
            ),
            Style::new(
                "account",
                format!("m/{purpose}'/{coin}'/{{i}}'/0/0"),
                "Ledger Live, Trezor Suite, OneKey",
            )
            .aliases(&["ledger-live"]),
        ])
    }

    fn derive(&self, wallet: &Wallet, path: &DerivationPath) -> Result<Account, Error> {
        let node = bip32::Node::derive(wallet.seed(), path)?;
        let secret = node.private_key();
        let public_key = node.public_key();

        let address = match self.kind {
            Kind::P2pkh => encoding::segwit::p2pkh(self.network.p2pkh_version(), &public_key),
            Kind::P2shP2wpkh => {
                encoding::segwit::p2sh_p2wpkh(self.network.p2sh_version(), &public_key)
            }
            Kind::P2wpkh => encoding::segwit::p2wpkh(self.network.hrp(), &public_key)?,
            Kind::P2tr => p2tr(&public_key, self.network)?,
        };

        Ok(Account::new(
            path.clone(),
            address,
            hex::encode(public_key),
            encoding::base58::wif(self.network.wif_version(), &secret)?,
            SecretKey::Secp256k1(secret),
        ))
    }
}

/// BIP-86 key-path-only P2TR: `Q = lift_x(P) + hashTapTweak(x)·G`, address =
/// bech32m over the x-coordinate of `Q`.
fn p2tr(public_key: &[u8; 33], network: Network) -> Result<String, Error> {
    use k256::elliptic_curve::ops::Reduce;
    use k256::elliptic_curve::sec1::ToSec1Point;
    use sha2::{Digest as _, Sha256};

    let internal_x = public_key.split_at(1).1;
    let mut even_key = Vec::with_capacity(33);
    even_key.push(0x02);
    even_key.extend_from_slice(internal_x);
    let internal = k256::PublicKey::from_sec1_bytes(&even_key)
        .map_err(|e| Error::InvalidKey(format!("p2tr internal key: {e}")))?;

    let tag = Sha256::digest(b"TapTweak");
    let tweak_bytes: [u8; 32] = Sha256::new()
        .chain_update(tag)
        .chain_update(tag)
        .chain_update(internal_x)
        .finalize()
        .into();
    // BIP-341: t = int(hashTapTweak(x)) mod n (reduced, not rejected).
    let tweak = <k256::Scalar as Reduce<k256::FieldBytes>>::reduce(&tweak_bytes.into());

    let q = k256::ProjectivePoint::from(*internal.as_affine())
        + k256::ProjectivePoint::GENERATOR * tweak;
    let encoded = q.to_affine().to_sec1_point(true);
    let output_x = encoded
        .x()
        .ok_or_else(|| Error::InvalidKey(String::from("p2tr output key at infinity")))?;

    bech32::segwit::encode_v1(network.hrp(), output_x)
        .map_err(|e| Error::InvalidKey(format!("bech32m: {e}")))
}
