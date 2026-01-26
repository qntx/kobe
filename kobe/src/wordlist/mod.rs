//! BIP-39 wordlists for mnemonic phrase generation.
//!
//! Supports Chinese (Simplified/Traditional), English, French, Italian,
//! Japanese, Korean, and Spanish.

pub mod bip39;

pub use self::bip39::Language;
pub use crate::traits::{Wordlist, WordlistError};
