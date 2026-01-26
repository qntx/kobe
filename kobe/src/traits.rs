//! Core traits defining the wallet interface.
//!
//! All wallet-related traits are defined here for easy discovery and consistency.

use crate::error::Result;
use core::fmt::{self, Debug, Display};
use core::hash::Hash;
use k256::elliptic_curve::rand_core::{CryptoRng, RngCore};

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// A private key that can sign messages and derive public keys.
///
/// # Thread Safety
/// This trait requires `Send + Sync` to allow wallet operations in async contexts.
pub trait PrivateKey: Clone + Debug + Sized + zeroize::Zeroize + Send + Sync {
    /// The associated public key type
    type PublicKey: PublicKey;

    /// Generate a new random private key
    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self>;

    /// Create from raw bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self>;

    /// Serialize to raw bytes
    fn to_bytes(&self) -> [u8; 32];

    /// Derive the corresponding public key
    fn public_key(&self) -> Self::PublicKey;

    /// Sign a message hash (prehashed data)
    fn sign_prehash(&self, hash: &[u8; 32]) -> Result<Signature>;
}

/// A public key that can verify signatures and derive addresses.
///
/// # Thread Safety
/// This trait requires `Send + Sync` to allow wallet operations in async contexts.
pub trait PublicKey: Clone + Debug + PartialEq + Eq + Sized + Send + Sync {
    /// The associated address type
    type Address: Address;

    /// Create from compressed bytes (33 bytes for secp256k1)
    fn from_bytes(bytes: &[u8]) -> Result<Self>;

    /// Serialize to compressed bytes
    fn to_bytes(&self) -> [u8; 33];

    /// Serialize to uncompressed bytes (65 bytes with 0x04 prefix)
    fn to_uncompressed_bytes(&self) -> [u8; 65];

    /// Derive the address
    fn to_address(&self) -> Self::Address;

    /// Verify a signature
    fn verify(&self, hash: &[u8; 32], signature: &Signature) -> Result<()>;
}

/// A cryptocurrency address.
///
/// # Thread Safety
/// This trait requires `Send + Sync` and `Hash` for use in collections and async contexts.
pub trait Address: Clone + Debug + Display + PartialEq + Eq + Hash + Sized + Send + Sync {
    /// Parse from string representation
    #[cfg(feature = "alloc")]
    fn from_str(s: &str) -> Result<Self>;

    /// Convert to string representation
    #[cfg(feature = "alloc")]
    fn to_string(&self) -> String;

    /// Get the raw bytes of the address
    fn as_bytes(&self) -> &[u8];
}

/// An ECDSA signature with recovery ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// The r component (32 bytes)
    pub r: [u8; 32],
    /// The s component (32 bytes)
    pub s: [u8; 32],
    /// The recovery ID (0-3)
    pub v: u8,
}

impl Signature {
    /// Create a new signature from components
    pub const fn new(r: [u8; 32], s: [u8; 32], v: u8) -> Self {
        Self { r, s, v }
    }

    /// Create from 64-byte RS format plus recovery ID
    pub fn from_rs_v(rs: [u8; 64], v: u8) -> Self {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&rs[..32]);
        s.copy_from_slice(&rs[32..]);
        Self { r, s, v }
    }

    /// Serialize to 64-byte RS format
    pub fn to_rs(&self) -> [u8; 64] {
        let mut result = [0u8; 64];
        result[..32].copy_from_slice(&self.r);
        result[32..].copy_from_slice(&self.s);
        result
    }

    /// Serialize to 65-byte RSV format
    pub fn to_rsv(&self) -> [u8; 65] {
        let mut result = [0u8; 65];
        result[..32].copy_from_slice(&self.r);
        result[32..64].copy_from_slice(&self.s);
        result[64] = self.v;
        result
    }

    /// Serialize to 65-byte VRS format (used by some chains)
    pub fn to_vrs(&self) -> [u8; 65] {
        let mut result = [0u8; 65];
        result[0] = self.v;
        result[1..33].copy_from_slice(&self.r);
        result[33..].copy_from_slice(&self.s);
        result
    }

    /// Serialize to DER format for Bitcoin transactions.
    ///
    /// Returns a variable-length DER-encoded signature (typically 70-72 bytes).
    #[cfg(feature = "alloc")]
    pub fn to_der(&self) -> alloc::vec::Vec<u8> {
        // DER encoding: 0x30 [total-len] 0x02 [r-len] [r] 0x02 [s-len] [s]
        let mut r = self.r.to_vec();
        let mut s = self.s.to_vec();

        // Remove leading zeros but keep one if high bit is set
        while r.len() > 1 && r[0] == 0 && r[1] < 0x80 {
            r.remove(0);
        }
        while s.len() > 1 && s[0] == 0 && s[1] < 0x80 {
            s.remove(0);
        }

        // Add leading zero if high bit is set (to prevent negative interpretation)
        if r[0] >= 0x80 {
            r.insert(0, 0);
        }
        if s[0] >= 0x80 {
            s.insert(0, 0);
        }

        let mut der = alloc::vec::Vec::with_capacity(6 + r.len() + s.len());
        der.push(0x30); // SEQUENCE
        der.push((4 + r.len() + s.len()) as u8); // Total length
        der.push(0x02); // INTEGER
        der.push(r.len() as u8);
        der.extend_from_slice(&r);
        der.push(0x02); // INTEGER
        der.push(s.len() as u8);
        der.extend_from_slice(&s);

        der
    }
}

/// Extended key for hierarchical deterministic wallets (BIP-32).
///
/// # Thread Safety
/// This trait requires `Send + Sync` to allow wallet operations in async contexts.
pub trait ExtendedPrivateKey: Clone + Debug + Sized + zeroize::Zeroize + Send + Sync {
    /// The associated private key type
    type PrivateKey: PrivateKey;

    /// Create master key from seed
    fn from_seed(seed: &[u8]) -> Result<Self>;

    /// Derive child key at given index (normal derivation)
    fn derive_child(&self, index: u32) -> Result<Self>;

    /// Derive child key at given index (hardened derivation)
    fn derive_child_hardened(&self, index: u32) -> Result<Self>;

    /// Derive from path string (e.g., "m/44'/60'/0'/0/0")
    #[cfg(feature = "alloc")]
    fn derive_path(&self, path: &str) -> Result<Self>;

    /// Get the underlying private key
    fn private_key(&self) -> Self::PrivateKey;

    /// Get the chain code
    fn chain_code(&self) -> [u8; 32];

    /// Get the depth in the derivation tree
    fn depth(&self) -> u8;
}

/// Extended public key for hierarchical deterministic wallets (BIP-32).
///
/// Supports watch-only wallets and non-hardened child key derivation.
/// Cannot derive hardened children as that requires the private key.
///
/// # Thread Safety
/// This trait requires `Send + Sync` to allow wallet operations in async contexts.
pub trait ExtendedPublicKey: Clone + Debug + Sized + Send + Sync {
    /// The associated public key type
    type PublicKey: PublicKey;

    /// Create from extended private key
    fn from_extended_private_key<E: ExtendedPrivateKey>(xprv: &E) -> Result<Self>
    where
        E::PrivateKey: PrivateKey<PublicKey = Self::PublicKey>;

    /// Derive child key at given index (non-hardened only)
    ///
    /// Returns an error if attempting hardened derivation (index >= 2^31)
    fn derive_child(&self, index: u32) -> Result<Self>;

    /// Derive from path string (e.g., "m/0/1/2")
    ///
    /// Only supports non-hardened paths. Returns error if path contains hardened indices.
    #[cfg(feature = "alloc")]
    fn derive_path(&self, path: &str) -> Result<Self>;

    /// Get the underlying public key
    fn public_key(&self) -> Self::PublicKey;

    /// Get the chain code
    fn chain_code(&self) -> [u8; 32];

    /// Get the depth in the derivation tree
    fn depth(&self) -> u8;

    /// Get the parent fingerprint
    fn parent_fingerprint(&self) -> [u8; 4];

    /// Get the child index
    fn child_index(&self) -> u32;
}

/// Mnemonic phrase for seed generation (BIP-39).
///
/// # Thread Safety
/// This trait requires `Send + Sync` and `zeroize::Zeroize` for security and async contexts.
pub trait Mnemonic: Clone + Debug + Sized + zeroize::Zeroize + Send + Sync {
    /// Generate new mnemonic with specified word count (12, 15, 18, 21, 24)
    fn generate<R: RngCore + CryptoRng>(rng: &mut R, word_count: usize) -> Result<Self>;

    /// Create from existing phrase
    #[cfg(feature = "alloc")]
    fn from_phrase(phrase: &str) -> Result<Self>;

    /// Get the phrase as string
    #[cfg(feature = "alloc")]
    fn to_phrase(&self) -> String;

    /// Derive seed with optional passphrase
    fn to_seed(&self, passphrase: &str) -> [u8; 64];

    /// Get entropy bytes
    fn entropy(&self) -> &[u8];
}

/// Trait for cryptocurrency amount types.
///
/// Provides type-safe handling of cryptocurrency amounts with unit conversions.
pub trait Amount:
    Copy + Clone + fmt::Debug + fmt::Display + PartialEq + Eq + PartialOrd + Ord + Send + Sync
{
    /// The number of decimal places for this currency.
    const DECIMALS: u8;

    /// The currency symbol or ticker.
    const SYMBOL: &'static str;

    /// Create from the smallest unit (satoshi, wei, etc.)
    fn from_base_units(value: u64) -> Self;

    /// Get the value in the smallest unit.
    fn to_base_units(&self) -> u64;

    /// Create from the main unit (BTC, ETH, etc.)
    fn from_main_units(value: f64) -> Self {
        let multiplier = 10u64.pow(Self::DECIMALS as u32);
        Self::from_base_units((value * multiplier as f64) as u64)
    }

    /// Get the value in the main unit.
    fn to_main_units(&self) -> f64 {
        let multiplier = 10u64.pow(Self::DECIMALS as u32);
        self.to_base_units() as f64 / multiplier as f64
    }

    /// Check if the amount is zero.
    fn is_zero(&self) -> bool {
        self.to_base_units() == 0
    }
}

/// Transaction identifier (hash).
pub trait TransactionId: Clone + Debug + Display + PartialEq + Eq + Hash + Send + Sync {
    /// Get the transaction ID as bytes.
    fn as_bytes(&self) -> &[u8];

    /// Get the transaction ID as hex string.
    #[cfg(feature = "alloc")]
    fn to_hex(&self) -> String {
        crate::encoding::to_hex(self.as_bytes())
    }
}

/// Trait for cryptocurrency transactions.
#[cfg(feature = "alloc")]
pub trait Transaction: Clone + Debug + Send + Sync {
    /// The private key type used to sign transactions.
    type PrivateKey: PrivateKey;

    /// The transaction ID type.
    type TransactionId: TransactionId;

    /// Sign the transaction with the given private key.
    fn sign(&self, private_key: &Self::PrivateKey) -> Result<Self>;

    /// Check if the transaction is signed.
    fn is_signed(&self) -> bool;

    /// Serialize the transaction to bytes.
    fn to_bytes(&self) -> Result<Vec<u8>>;

    /// Deserialize a transaction from bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self>;

    /// Get the transaction ID (hash).
    fn transaction_id(&self) -> Result<Self::TransactionId>;

    /// Get the serialized transaction as hex string.
    fn to_hex(&self) -> Result<String> {
        Ok(crate::encoding::to_hex(&self.to_bytes()?))
    }
}

/// The interface for a BIP-39 wordlist.
pub trait Wordlist: Copy + Clone + Debug + Send + Sync + 'static + Eq + Sized {
    /// Get the word at the given index.
    fn get_word(index: usize) -> Option<&'static str>;

    /// Get the index of the given word.
    fn get_index(word: &str) -> Option<usize>;

    /// Get all words in the wordlist.
    fn get_all() -> &'static [&'static str];
}

/// Errors related to wordlist operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WordlistError {
    /// Invalid index in wordlist.
    InvalidIndex(usize),
    /// Invalid word not found in wordlist.
    #[cfg(feature = "alloc")]
    InvalidWord(String),
    /// Invalid word (static message for no_std).
    #[cfg(not(feature = "alloc"))]
    InvalidWord,
}

impl Display for WordlistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIndex(i) => write!(f, "invalid wordlist index: {}", i),
            #[cfg(feature = "alloc")]
            Self::InvalidWord(w) => write!(f, "invalid word: {}", w),
            #[cfg(not(feature = "alloc"))]
            Self::InvalidWord => write!(f, "invalid word"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WordlistError {}
