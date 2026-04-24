//! Ethereum address derivation from an HD wallet seed.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use alloy_primitives::{Address, keccak256};
use kobe_primitives::{
    // Anonymous trait import so method-call syntax (`style.path(i)`,
    // `style.name()`, `DerivationStyle::all()`) resolves without shadowing
    // the local `DerivationStyle` enum.
    DerivationStyle as _,
    Derive,
    DeriveError,
    DerivedAccount,
    DerivedPublicKey,
    ParseDerivationStyleError,
    Wallet,
    derive_range,
};

/// Derivation path styles for different Ethereum wallet software.
///
/// MetaMask/Trezor, Ledger Live, and Ledger Legacy each use a different
/// BIP-44 path layout. See individual variant docs for details.
///
/// The chain-agnostic contract (path / name / all / `FromStr`) is defined
/// by the [`kobe_primitives::DerivationStyle`] trait; import it to call
/// [`path`](kobe_primitives::DerivationStyle::path),
/// [`name`](kobe_primitives::DerivationStyle::name), or
/// [`all`](kobe_primitives::DerivationStyle::all) through the trait.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum DerivationStyle {
    /// `m/44'/60'/0'/0/{index}` — `MetaMask`, Trezor, Exodus (most common).
    #[default]
    Standard,
    /// `m/44'/60'/{index}'/0/0` — Ledger Live.
    LedgerLive,
    /// `m/44'/60'/0'/{index}` — Ledger Legacy / MEW / `MyCrypto`.
    LedgerLegacy,
}

/// Every variant of [`DerivationStyle`] — returned by
/// [`kobe_primitives::DerivationStyle::all`].
const ALL_STYLES: &[DerivationStyle] = &[
    DerivationStyle::Standard,
    DerivationStyle::LedgerLive,
    DerivationStyle::LedgerLegacy,
];

/// Tokens accepted by [`DerivationStyle::from_str`] — surfaced in
/// [`ParseDerivationStyleError`] so CLI error messages are actionable.
const ACCEPTED_TOKENS: &[&str] = &[
    "standard",
    "metamask",
    "trezor",
    "bip44",
    "ledger-live",
    "ledgerlive",
    "live",
    "ledger-legacy",
    "ledgerlegacy",
    "legacy",
    "mew",
];

impl kobe_primitives::DerivationStyle for DerivationStyle {
    fn path(self, index: u32) -> String {
        match self {
            Self::Standard => format!("m/44'/60'/0'/0/{index}"),
            Self::LedgerLive => format!("m/44'/60'/{index}'/0/0"),
            Self::LedgerLegacy => format!("m/44'/60'/0'/{index}"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Standard => "Standard (MetaMask/Trezor)",
            Self::LedgerLive => "Ledger Live",
            Self::LedgerLegacy => "Ledger Legacy",
        }
    }

    fn all() -> &'static [Self] {
        ALL_STYLES
    }
}

impl fmt::Display for DerivationStyle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(<Self as kobe_primitives::DerivationStyle>::name(*self))
    }
}

impl FromStr for DerivationStyle {
    type Err = ParseDerivationStyleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "standard" | "metamask" | "trezor" | "bip44" => Ok(Self::Standard),
            "ledger-live" | "ledgerlive" | "live" => Ok(Self::LedgerLive),
            "ledger-legacy" | "ledgerlegacy" | "legacy" | "mew" => Ok(Self::LedgerLegacy),
            _ => Err(ParseDerivationStyleError::new(
                "ethereum",
                s,
                ACCEPTED_TOKENS,
            )),
        }
    }
}

/// Ethereum address deriver.
#[derive(Debug)]
pub struct Deriver<'a> {
    /// Wallet seed reference.
    wallet: &'a Wallet,
}

impl<'a> Deriver<'a> {
    /// Create a deriver from a wallet.
    #[must_use]
    pub const fn new(wallet: &'a Wallet) -> Self {
        Self { wallet }
    }

    /// Derive with a specific [`DerivationStyle`].
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation fails.
    pub fn derive_with(
        &self,
        style: DerivationStyle,
        index: u32,
    ) -> Result<DerivedAccount, DeriveError> {
        self.derive_at(&style.path(index))
    }

    /// Derive `count` accounts starting at `start` with a specific style.
    ///
    /// # Errors
    ///
    /// Returns an error if any individual derivation fails or `start + count` overflows.
    pub fn derive_many_with(
        &self,
        style: DerivationStyle,
        start: u32,
        count: u32,
    ) -> Result<Vec<DerivedAccount>, DeriveError> {
        derive_range(start, count, |i| self.derive_with(style, i))
    }

    /// Derive at an arbitrary BIP-32 path.
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation fails.
    pub fn derive_at(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        let key = self.wallet.derive_secp256k1(path)?;
        let uncompressed = key.uncompressed_pubkey();

        let addr_hash = keccak256(&uncompressed[1..]);
        let (_, addr_bytes) = addr_hash.split_at(12);
        let address = Address::from_slice(addr_bytes);

        Ok(DerivedAccount::new(
            String::from(path),
            key.private_key_bytes(),
            DerivedPublicKey::Secp256k1Uncompressed(uncompressed),
            address.to_checksum(None),
        ))
    }
}

impl Derive for Deriver<'_> {
    type Account = DerivedAccount;
    type Error = DeriveError;

    fn derive(&self, index: u32) -> Result<DerivedAccount, DeriveError> {
        self.derive_with(DerivationStyle::Standard, index)
    }

    fn derive_path(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        self.derive_at(path)
    }
}

#[cfg(test)]
mod tests {
    use kobe_primitives::DeriveExt;

    use super::*;

    /// Canonical BIP-39 test mnemonic (12 × `abandon` + `about`).
    const MNEMONIC_ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// Hardhat / Foundry default test mnemonic. The resulting accounts are
    /// the most widely-known Ethereum test vectors; any library in the
    /// ecosystem that derives `m/44'/60'/0'/0/0` from this phrase yields
    /// `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` with private key
    /// `0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80`.
    /// See <https://hardhat.org/hardhat-network/docs/reference>.
    const MNEMONIC_HARDHAT: &str = "test test test test test test test test test test test junk";

    fn wallet() -> Wallet {
        Wallet::from_mnemonic(MNEMONIC_ABANDON, None).unwrap()
    }

    /// Strongest possible EVM KAT: Hardhat / Foundry / Anvil / ethers.js
    /// all agree on these values. A mismatch here means the BIP-32 /
    /// secp256k1 / keccak256 / EIP-55 pipeline is broken in a way that
    /// affects every Ethereum user of the library.
    #[test]
    fn kat_evm_hardhat_default_index0() {
        let w = Wallet::from_mnemonic(MNEMONIC_HARDHAT, None).unwrap();
        let a = Deriver::new(&w).derive(0).unwrap();
        assert_eq!(a.path(), "m/44'/60'/0'/0/0");
        assert_eq!(a.address(), "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        assert_eq!(
            a.private_key_hex().as_str(),
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        );
    }

    #[test]
    fn kat_evm_hardhat_default_index1() {
        let w = Wallet::from_mnemonic(MNEMONIC_HARDHAT, None).unwrap();
        let a = Deriver::new(&w).derive(1).unwrap();
        assert_eq!(a.path(), "m/44'/60'/0'/0/1");
        assert_eq!(a.address(), "0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
        assert_eq!(
            a.private_key_hex().as_str(),
            "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
        );
    }

    /// Second KAT on the canonical BIP-39 `abandon…about` mnemonic so we
    /// also stress the BIP-39 PBKDF2 path that Hardhat skips (since Hardhat
    /// uses a different 12-word phrase).
    #[test]
    fn kat_evm_abandon_index0() {
        let a = Deriver::new(&wallet()).derive(0).unwrap();
        assert_eq!(a.path(), "m/44'/60'/0'/0/0");
        assert_eq!(a.address(), "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
        assert_eq!(
            a.private_key_hex().as_str(),
            "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727"
        );
    }

    #[test]
    fn kat_evm_abandon_index1() {
        let a = Deriver::new(&wallet()).derive(1).unwrap();
        assert_eq!(a.path(), "m/44'/60'/0'/0/1");
        assert_eq!(a.address(), "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0");
        assert_eq!(
            a.private_key_hex().as_str(),
            "9a983cb3d832fbde5ab49d692b7a8bf5b5d232479c99333d0fc8e1d21f1b55b6"
        );
    }

    /// Each derivation style must produce a distinct address at index 1 —
    /// guards against two styles collapsing onto the same path.
    #[test]
    fn derivation_styles_produce_distinct_addresses() {
        let w = wallet();
        let d = Deriver::new(&w);
        let standard = d.derive_with(DerivationStyle::Standard, 1).unwrap();
        let live = d.derive_with(DerivationStyle::LedgerLive, 1).unwrap();
        let legacy = d.derive_with(DerivationStyle::LedgerLegacy, 1).unwrap();
        assert_eq!(standard.path(), "m/44'/60'/0'/0/1");
        assert_eq!(live.path(), "m/44'/60'/1'/0/0");
        assert_eq!(legacy.path(), "m/44'/60'/0'/1");
        assert_ne!(standard.address(), live.address());
        assert_ne!(standard.address(), legacy.address());
        assert_ne!(live.address(), legacy.address());
    }

    /// `DerivationStyle::path` must mint the canonical path strings.
    #[test]
    fn derivation_style_path_shapes() {
        assert_eq!(DerivationStyle::Standard.path(0), "m/44'/60'/0'/0/0");
        assert_eq!(DerivationStyle::LedgerLive.path(1), "m/44'/60'/1'/0/0");
        assert_eq!(DerivationStyle::LedgerLegacy.path(2), "m/44'/60'/0'/2");
    }

    /// `DerivationStyle::FromStr` must map aliases and reject unknowns.
    #[test]
    fn derivation_style_from_str_accepts_aliases() {
        assert_eq!(
            "standard".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::Standard
        );
        assert_eq!(
            "metamask".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::Standard
        );
        assert_eq!(
            "ledger-live".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::LedgerLive
        );
        assert_eq!(
            "legacy".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::LedgerLegacy
        );
        assert!("definitely-not-a-style".parse::<DerivationStyle>().is_err());
    }

    /// `derive_many` must agree with scalar `derive` for every index.
    #[test]
    fn derive_many_matches_individual() {
        let w = wallet();
        let d = Deriver::new(&w);
        let batch = d.derive_many(0, 5).unwrap();
        let single: Vec<_> = (0..5).map(|i| d.derive(i).unwrap()).collect();
        for (b, s) in batch.iter().zip(single.iter()) {
            assert_eq!(b.address(), s.address());
            assert_eq!(b.path(), s.path());
        }
    }

    #[test]
    fn passphrase_changes_derivation() {
        let w = Wallet::from_mnemonic(MNEMONIC_ABANDON, Some("TREZOR")).unwrap();
        assert_ne!(
            Deriver::new(&wallet()).derive(0).unwrap().address(),
            Deriver::new(&w).derive(0).unwrap().address(),
        );
    }
}
