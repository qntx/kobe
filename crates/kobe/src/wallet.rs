//! The [`Wallet`]: a BIP-39 mnemonic + passphrase plus the derived seed.

#[cfg(feature = "os-rng")]
use alloc::format;
use alloc::string::{String, ToString};
use core::str::FromStr;

use bip39::{Language, Mnemonic};
use zeroize::Zeroizing;

use crate::Error;

/// Number of words in a BIP-39 mnemonic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum WordCount {
    /// 12 words (128-bit entropy).
    #[default]
    W12,
    /// 15 words (160-bit entropy).
    W15,
    /// 18 words (192-bit entropy).
    W18,
    /// 21 words (224-bit entropy).
    W21,
    /// 24 words (256-bit entropy).
    W24,
}

impl WordCount {
    /// Number of mnemonic words.
    #[must_use]
    pub const fn words(self) -> usize {
        match self {
            Self::W12 => 12,
            Self::W15 => 15,
            Self::W18 => 18,
            Self::W21 => 21,
            Self::W24 => 24,
        }
    }

    /// Entropy length in bytes.
    #[must_use]
    pub const fn entropy_len(self) -> usize {
        self.words() / 3 * 4
    }
}

impl TryFrom<usize> for WordCount {
    type Error = Error;

    fn try_from(n: usize) -> Result<Self, Self::Error> {
        match n {
            12 => Ok(Self::W12),
            15 => Ok(Self::W15),
            18 => Ok(Self::W18),
            21 => Ok(Self::W21),
            24 => Ok(Self::W24),
            n => Err(Error::WordCount(n.to_string())),
        }
    }
}

impl FromStr for WordCount {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "12" => Ok(Self::W12),
            "15" => Ok(Self::W15),
            "18" => Ok(Self::W18),
            "21" => Ok(Self::W21),
            "24" => Ok(Self::W24),
            _ => Err(Error::WordCount(String::from(s))),
        }
    }
}

/// An HD wallet: a BIP-39 mnemonic, its passphrase, and the derived seed.
///
/// `passphrase` is `""` when none was supplied (BIP-39 semantics). Debug
/// output is redacted; all secret state zeroizes on drop.
pub struct Wallet {
    mnemonic: Zeroizing<String>,
    passphrase: Zeroizing<String>,
    /// Read via [`Self::seed`] by the chain modules; retained in minimal
    /// no-chain builds so generation/import always carry the seed.
    #[allow(dead_code, reason = "read only via feature-gated chain modules")]
    seed: Zeroizing<[u8; 64]>,
    /// The BIP-39 entropy behind `mnemonic` (16–32 bytes), for chains whose
    /// master-key generation reads entropy directly (Cardano CIP-3).
    #[allow(dead_code, reason = "read only via feature-gated chain modules")]
    entropy: Zeroizing<alloc::vec::Vec<u8>>,
}

impl Wallet {
    /// Generate a fresh wallet using a caller-supplied cryptographic RNG.
    ///
    /// Works in `no_std` environments where an OS RNG is unavailable.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Mnemonic`] if the generated entropy cannot be
    /// encoded (the length is valid by construction, so this cannot fail
    /// in practice).
    pub fn generate<R: rand_core::CryptoRng + ?Sized>(
        rng: &mut R,
        words: WordCount,
        passphrase: &str,
    ) -> Result<Self, Error> {
        let mut entropy = Zeroizing::new(alloc::vec![0u8; words.entropy_len()]);
        rand_core::Rng::fill_bytes(rng, entropy.as_mut_slice());
        Self::from_entropy(entropy.as_slice(), passphrase)
    }

    /// Generate a fresh wallet using the operating system RNG.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Rng`] if the OS random source fails.
    #[cfg(feature = "os-rng")]
    pub fn random(words: WordCount, passphrase: &str) -> Result<Self, Error> {
        let mut entropy = Zeroizing::new(alloc::vec![0u8; words.entropy_len()]);
        getrandom::fill(entropy.as_mut_slice()).map_err(|e| Error::Rng(format!("{e}")))?;
        Self::from_entropy(&entropy, passphrase)
    }

    /// Import a wallet from a BIP-39 mnemonic phrase (strict English).
    ///
    /// The phrase is NFKD-normalized, then checked against the English
    /// wordlist including the checksum.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Mnemonic`] if the phrase is not a valid BIP-39
    /// English mnemonic.
    pub fn from_mnemonic(phrase: &str, passphrase: &str) -> Result<Self, Error> {
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(|e| Error::Mnemonic(e.to_string()))?;
        Ok(Self::from_parts(mnemonic, passphrase))
    }

    /// Import a wallet from raw entropy bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EntropyLength`] if `entropy` is not 16, 20, 24, 28 or
    /// 32 bytes.
    pub fn from_entropy(entropy: &[u8], passphrase: &str) -> Result<Self, Error> {
        if !matches!(entropy.len(), 16 | 20 | 24 | 28 | 32) {
            return Err(Error::EntropyLength(entropy.len()));
        }
        let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy)
            .map_err(|e| Error::Mnemonic(e.to_string()))?;
        Ok(Self::from_parts(mnemonic, passphrase))
    }

    fn from_parts(mnemonic: Mnemonic, passphrase: &str) -> Self {
        let mnemonic = Zeroizing::new(mnemonic);
        // Join `words()` into a pre-sized buffer instead of `to_string()` —
        // no reallocation ever holds half-written secret characters.
        let mut phrase = Zeroizing::new(String::with_capacity(
            mnemonic
                .words()
                .map(|w| w.len() + 1)
                .sum::<usize>()
                .saturating_sub(1),
        ));
        for (i, word) in mnemonic.words().enumerate() {
            if i > 0 {
                phrase.push(' ');
            }
            phrase.push_str(word);
        }
        Self {
            seed: Zeroizing::new(mnemonic.to_seed(passphrase)),
            entropy: Zeroizing::new(mnemonic.to_entropy()),
            mnemonic: phrase,
            passphrase: Zeroizing::new(String::from(passphrase)),
        }
    }

    /// The normalized BIP-39 mnemonic phrase.
    ///
    /// **Sensitive**: this phrase reconstructs every derived key.
    #[must_use]
    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }

    /// Whether a non-empty BIP-39 passphrase was supplied.
    #[must_use]
    pub fn has_passphrase(&self) -> bool {
        !self.passphrase.is_empty()
    }

    /// The 64-byte BIP-39 seed (crate-internal; chains derive from it).
    #[allow(dead_code, reason = "used by feature-gated chain modules only")]
    pub(crate) fn seed(&self) -> &[u8; 64] {
        &self.seed
    }

    /// The BIP-39 entropy, 16–32 bytes (crate-internal; Cardano CIP-3).
    #[allow(dead_code, reason = "used by feature-gated chain modules only")]
    pub(crate) fn entropy(&self) -> &[u8] {
        &self.entropy
    }

    /// The BIP-39 passphrase, `""` when unset (crate-internal).
    #[allow(dead_code, reason = "used by feature-gated chain modules only")]
    pub(crate) fn passphrase(&self) -> &str {
        &self.passphrase
    }

    /// The BIP-32 master-key fingerprint: the first 4 bytes of HASH160 of
    /// the compressed master public key — the same 8-hex-digit id Sparrow
    /// and Coldcard show. Not secret.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKey`] when the master key cannot be derived.
    #[cfg(feature = "camouflage")]
    pub fn fingerprint(&self) -> Result<[u8; 4], Error> {
        use sha2::Digest as _;

        let node = crate::hd::bip32::Node::derive(self.seed(), &crate::DerivationPath::default())?;
        let hash160 = ripemd::Ripemd160::digest(sha2::Sha256::digest(node.public_key()));
        let mut out = [0u8; 4];
        out.copy_from_slice(hash160.get(0..4).unwrap_or(&[]));
        Ok(out)
    }
}

impl core::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Wallet")
            .field("mnemonic", &"[REDACTED]")
            .field("passphrase", &"[REDACTED]")
            .field("seed", &"[REDACTED]")
            .field("entropy", &"[REDACTED]")
            .field("has_passphrase", &self.has_passphrase())
            .finish()
    }
}
