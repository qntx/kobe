//! Wordlists for mnemonic phrase generation.
//!
//! - **BIP-39**: Standard wordlists for Bitcoin/Ethereum mnemonics
//! - **Monero**: Wordlists specific to Monero wallets

pub mod bip39;
pub mod monero;

pub use self::bip39::Language;
pub use crate::traits::{Wordlist, WordlistError};
