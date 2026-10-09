//! Unified wallet type for multi-chain key derivation.

use alloc::string::{String, ToString};

use bip39::Mnemonic;
use zeroize::Zeroizing;

use crate::Error;

/// Domain separation tag for [`Wallet::id`]: concatenated as raw UTF-8
/// bytes (no length prefix) in front of the compressed BIP-32 master
/// public key before hashing.
#[cfg(feature = "bip32")]
const WALLET_ID_DOMAIN: &[u8] = b"kobe/wallet-id/v1";

/// Entropy length in bytes for a BIP-39 word count (12 words = 128 bits, …).
fn entropy_len(word_count: usize) -> Result<usize, Error> {
    match word_count {
        12 => Ok(16),
        15 => Ok(20),
        18 => Ok(24),
        21 => Ok(28),
        24 => Ok(32),
        _ => Err(Error::Input(alloc::format!(
            "word count must be 12, 15, 18, 21, or 24, got {word_count}"
        ))),
    }
}

/// A unified HD wallet that can derive keys for multiple cryptocurrencies.
///
/// This wallet holds a BIP-39 mnemonic and a derived 64-byte seed used by
/// [`Self::derive_secp256k1`] / [`Self::derive_ed25519`] (and the chain
/// derivers built on them). The raw seed is **not** part of the default
/// public API; enable the `raw-seed` feature only if an advanced caller
/// truly needs [`Self::seed`].
///
/// # Passphrase Support
///
/// The wallet supports an optional BIP39 passphrase (sometimes called "25th word").
/// This provides an extra layer of security - the same mnemonic with different
/// passphrases will produce completely different wallets.
pub struct Wallet {
    /// BIP39 mnemonic phrase (English wordlist).
    mnemonic: Zeroizing<String>,
    /// Seed derived from mnemonic + passphrase.
    ///
    /// Read via [`Self::derive_secp256k1`] / [`Self::derive_ed25519`] or the
    /// feature-gated [`Self::seed`]. Marked `allow(dead_code)` so a minimal
    /// `alloc`-only build (no bip32/slip10/raw-seed) still retains the seed
    /// for future derive calls without a false-positive lint.
    #[allow(
        dead_code,
        reason = "read by derive_* / raw-seed; retained when those features are off"
    )]
    seed: Zeroizing<[u8; 64]>,
    /// Whether a passphrase was used.
    has_passphrase: bool,
}

impl core::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print mnemonic or seed — Zeroizing's Debug is not redacting.
        f.debug_struct("Wallet")
            .field("mnemonic", &"[REDACTED]")
            .field("seed", &"[REDACTED]")
            .field("has_passphrase", &self.has_passphrase)
            .field("word_count", &self.word_count())
            .finish()
    }
}

impl Wallet {
    /// Generate a new wallet with a random mnemonic using the OS RNG.
    ///
    /// # Arguments
    ///
    /// * `word_count` - Number of words (12, 15, 18, 21, or 24)
    /// * `passphrase` - Optional BIP39 passphrase for additional security
    ///
    /// # Errors
    ///
    /// Returns [`Error::Input`] if the word count is not 12, 15, 18, 21,
    /// or 24, or [`Error::Crypto`] if the OS random source fails.
    ///
    /// # Note
    ///
    /// This function requires the `os-rng` feature to be enabled.
    #[cfg(feature = "os-rng")]
    pub fn generate(word_count: usize, passphrase: Option<&str>) -> Result<Self, Error> {
        let mut entropy = Zeroizing::new(alloc::vec![0u8; entropy_len(word_count)?]);
        getrandom::fill(entropy.as_mut_slice())
            .map_err(|e| Error::Crypto(alloc::format!("os rng failed: {e}")))?;
        Self::from_entropy(&entropy, passphrase)
    }

    /// Generate a new wallet with a caller-supplied random number generator.
    ///
    /// This is useful in `no_std` environments where you provide your own
    /// cryptographically secure RNG instead of relying on the system RNG.
    ///
    /// # Arguments
    ///
    /// * `rng` - A cryptographically secure random number generator
    /// * `word_count` - Number of words (12, 15, 18, 21, or 24)
    /// * `passphrase` - Optional BIP39 passphrase for additional security
    ///
    /// # Errors
    ///
    /// Returns [`Error::Input`] if the word count is not 12, 15, 18, 21,
    /// or 24.
    pub fn generate_with<R>(
        rng: &mut R,
        word_count: usize,
        passphrase: Option<&str>,
    ) -> Result<Self, Error>
    where
        R: rand_core::CryptoRng + ?Sized,
    {
        let mut entropy = Zeroizing::new(alloc::vec![0u8; entropy_len(word_count)?]);
        rng.fill_bytes(entropy.as_mut_slice());
        Self::from_entropy(&entropy, passphrase)
    }

    /// Create a wallet from raw entropy bytes.
    ///
    /// This is useful in `no_std` environments where you provide your own entropy
    /// source instead of relying on the system RNG.
    ///
    /// # Arguments
    ///
    /// * `entropy` - Raw entropy bytes (16, 20, 24, 28, or 32 bytes for 12-24 words)
    /// * `passphrase` - Optional BIP39 passphrase for additional security
    ///
    /// # Errors
    ///
    /// Returns [`Error::Input`] if the entropy is not 16, 20, 24, 28, or
    /// 32 bytes long.
    pub fn from_entropy(entropy: &[u8], passphrase: Option<&str>) -> Result<Self, Error> {
        // Reject bad lengths as caller input, matching the shared error codes.
        if !matches!(entropy.len(), 16 | 20 | 24 | 28 | 32) {
            return Err(Error::Input(alloc::format!(
                "entropy length must be 16, 20, 24, 28, or 32 bytes, got {}",
                entropy.len()
            )));
        }
        let mnemonic = Mnemonic::from_entropy(entropy)?;
        Ok(Self::from_parts(&mnemonic, passphrase))
    }

    /// Create a wallet from an existing mnemonic phrase.
    ///
    /// # Arguments
    ///
    /// * `phrase` - BIP39 mnemonic phrase
    /// * `passphrase` - Optional BIP39 passphrase
    ///
    /// # Errors
    ///
    /// Returns an error if the mnemonic is invalid.
    pub fn from_mnemonic(phrase: &str, passphrase: Option<&str>) -> Result<Self, Error> {
        let mnemonic: Mnemonic = phrase.parse()?;
        Ok(Self::from_parts(&mnemonic, passphrase))
    }

    /// Expand 4-letter BIP-39 English prefixes then import (same path as CLI `import`).
    ///
    /// Full words pass through [`mnemonic::expand`](crate::mnemonic::expand) unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error if expansion or BIP-39 parse fails.
    pub fn from_mnemonic_expanded(phrase: &str, passphrase: Option<&str>) -> Result<Self, Error> {
        let expanded = crate::mnemonic::expand(phrase)?;
        Self::from_mnemonic(&expanded, passphrase)
    }

    /// Build a wallet from a validated mnemonic, deriving the seed.
    fn from_parts(mnemonic: &Mnemonic, passphrase: Option<&str>) -> Self {
        let passphrase_str = passphrase.unwrap_or("");
        let seed_bytes = mnemonic.to_seed(passphrase_str);
        Self {
            mnemonic: Zeroizing::new(mnemonic.to_string()),
            seed: Zeroizing::new(seed_bytes),
            has_passphrase: passphrase.is_some(),
        }
    }

    /// Get the mnemonic phrase.
    ///
    /// **Security Warning**: Handle this value carefully as it can
    /// reconstruct all derived keys.
    #[inline]
    #[must_use]
    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }

    /// Get the 64-byte BIP-39 seed, still wrapped in [`Zeroizing`].
    ///
    /// **Gated on the `raw-seed` feature** (off by default). Preferred
    /// entry points for key material are
    /// [`derive_secp256k1`](Self::derive_secp256k1) and
    /// [`derive_ed25519`](Self::derive_ed25519), which keep the seed inside
    /// [`Wallet`].
    ///
    /// Callers that enable `raw-seed` must treat the returned reference as
    /// highly sensitive: keep it borrowed or copy into another
    /// [`Zeroizing`] container.
    #[cfg(any(feature = "raw-seed", test))]
    #[inline]
    #[must_use]
    pub const fn seed(&self) -> &Zeroizing<[u8; 64]> {
        &self.seed
    }

    /// Derive a secp256k1 key pair at the given BIP-32 path.
    ///
    /// Preferred entry point for chains that derive secp256k1 keys (EVM,
    /// BTC, Cosmos, Tron, Spark, Filecoin, XRP Ledger, Nostr).
    /// Keeps the underlying seed encapsulated within [`Wallet`].
    ///
    /// # Errors
    ///
    /// Returns an error if the path is malformed or derivation fails.
    #[cfg(feature = "bip32")]
    #[inline]
    pub fn derive_secp256k1(&self, path: &str) -> Result<crate::bip32::DerivedSecp256k1Key, Error> {
        crate::bip32::DerivedSecp256k1Key::derive(self.seed.as_slice(), path)
    }

    /// Derive an Ed25519 key pair at the given SLIP-10 path.
    ///
    /// Preferred entry point for chains that derive Ed25519 keys (Solana,
    /// Sui, Aptos, TON). Keeps the underlying seed encapsulated within
    /// [`Wallet`].
    ///
    /// # Errors
    ///
    /// Returns an error if the path is malformed or derivation fails.
    #[cfg(feature = "slip10")]
    #[inline]
    pub fn derive_ed25519(&self, path: &str) -> Result<crate::slip10::DerivedEd25519Key, Error> {
        crate::slip10::DerivedEd25519Key::derive_path(self.seed.as_slice(), path)
    }

    /// Stable, non-secret identifier for this wallet.
    ///
    /// The id is the first 16 hex characters (8 bytes) of
    /// `SHA-256(b"kobe/wallet-id/v1" || master_pubkey)`, where
    /// `master_pubkey` is the 33-byte compressed secp256k1 public key of
    /// the BIP-32 root node (`m`) derived from the BIP-39 seed. The domain
    /// separator is concatenated as raw UTF-8 bytes — no length prefix.
    ///
    /// The id commits to the whole wallet (mnemonic + passphrase) without
    /// revealing key material and is safe to expose. Different mnemonics —
    /// or the same mnemonic with a different passphrase — produce
    /// different ids.
    ///
    /// # Errors
    ///
    /// Returns an error if the BIP-32 master key cannot be derived.
    #[cfg(feature = "bip32")]
    pub fn id(&self) -> Result<String, Error> {
        use sha2::Digest as _;

        let master = crate::bip32::DerivedSecp256k1Key::derive(self.seed.as_slice(), "m")?;
        let digest = sha2::Sha256::new()
            .chain_update(WALLET_ID_DOMAIN)
            .chain_update(master.compressed_pubkey())
            .finalize();
        Ok(hex::encode(digest.split_at(8).0))
    }

    /// Check if a passphrase was supplied at construction time.
    ///
    /// Returns `true` whenever the caller passed `Some(_)` to the constructor,
    /// even if the passphrase string itself was empty. Callers relying on
    /// "non-empty passphrase" semantics must check the passphrase string before
    /// constructing the wallet.
    #[must_use]
    pub const fn has_passphrase(&self) -> bool {
        self.has_passphrase
    }

    /// Get the word count of the mnemonic.
    #[inline]
    #[must_use]
    pub fn word_count(&self) -> usize {
        self.mnemonic.split_whitespace().count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    struct ZeroRng;

    impl rand_core::TryRng for ZeroRng {
        type Error = rand_core::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(0)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(0)
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            dst.fill(0);
            Ok(())
        }
    }

    impl rand_core::TryCryptoRng for ZeroRng {}

    #[cfg(feature = "os-rng")]
    #[test]
    fn test_generate_12_words() {
        let wallet = Wallet::generate(12, None).unwrap();
        assert_eq!(wallet.word_count(), 12);
        assert!(!wallet.has_passphrase());
    }

    #[cfg(feature = "os-rng")]
    #[test]
    fn test_generate_24_words() {
        let wallet = Wallet::generate(24, None).unwrap();
        assert_eq!(wallet.word_count(), 24);
    }

    #[cfg(feature = "os-rng")]
    #[test]
    fn test_generate_with_passphrase() {
        let wallet = Wallet::generate(12, Some("secret")).unwrap();
        assert!(wallet.has_passphrase());
    }

    #[test]
    fn test_generate_with_rng() {
        let mut rng = ZeroRng;
        let wallet = Wallet::generate_with(&mut rng, 12, None).unwrap();
        // All-zero 128-bit entropy → canonical abandon…about mnemonic.
        assert_eq!(wallet.mnemonic(), TEST_MNEMONIC);
    }

    #[test]
    fn test_generate_with_bad_word_count() {
        let mut rng = ZeroRng;
        let result = Wallet::generate_with(&mut rng, 13, None);
        assert!(matches!(result, Err(Error::Input(_))));
    }

    #[test]
    fn test_invalid_entropy_length() {
        // 15 bytes is invalid (should be 16, 20, 24, 28, or 32)
        let result = Wallet::from_entropy(&[0u8; 15], None);
        assert!(matches!(result, Err(Error::Input(_))));
    }

    #[test]
    fn test_from_entropy() {
        // 16 bytes = 12 words
        let entropy = [0u8; 16];
        let wallet = Wallet::from_entropy(&entropy, None).unwrap();
        assert_eq!(wallet.word_count(), 12);
    }

    #[test]
    fn test_from_mnemonic() {
        let wallet = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        assert_eq!(wallet.mnemonic(), TEST_MNEMONIC);
    }

    #[test]
    fn test_passphrase_changes_seed() {
        let wallet1 = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        let wallet2 = Wallet::from_mnemonic(TEST_MNEMONIC, Some("password")).unwrap();

        // Same mnemonic with different passphrase should produce different seeds
        assert_ne!(wallet1.seed(), wallet2.seed());
    }

    #[test]
    fn test_deterministic_seed() {
        let wallet1 = Wallet::from_mnemonic(TEST_MNEMONIC, Some("test")).unwrap();
        let wallet2 = Wallet::from_mnemonic(TEST_MNEMONIC, Some("test")).unwrap();
        assert_eq!(wallet1.seed(), wallet2.seed());
    }

    #[test]
    fn kat_bip39_seed_vector() {
        // BIP-39 reference: "abandon...about" with empty passphrase
        // Verified against Python pbkdf2_hmac + iancoleman.io
        let wallet = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        assert_eq!(
            hex::encode(wallet.seed()),
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        );
    }

    #[test]
    fn debug_redacts_mnemonic_and_seed() {
        let wallet = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        let dbg = alloc::format!("{wallet:?}");
        assert!(
            dbg.contains("[REDACTED]"),
            "expected redaction markers: {dbg}"
        );
        assert!(
            !dbg.contains("abandon"),
            "Debug must not leak mnemonic words: {dbg}"
        );
        // BIP-39 seed hex prefix for abandon…about
        assert!(
            !dbg.contains("5eb00bbddcf06908"),
            "Debug must not leak seed bytes: {dbg}"
        );
    }

    #[test]
    fn kat_all_zero_entropy_produces_abandon_about() {
        let wallet = Wallet::from_entropy(&[0u8; 16], None).unwrap();
        assert_eq!(wallet.mnemonic(), TEST_MNEMONIC);
    }
}
