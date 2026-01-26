//! Monero wordlists for mnemonic phrase generation.
//!
//! These wordlists are used by Monero wallets and differ from BIP-39 wordlists.

/// Chinese Simplified wordlist (1626 words).
pub const CHINESE_SIMPLIFIED: &str = include_str!("./monero/chinese_simplified.txt");
/// Dutch wordlist.
pub const DUTCH: &str = include_str!("./monero/dutch.txt");
/// English wordlist (1626 words).
pub const ENGLISH: &str = include_str!("./monero/english.txt");
/// Legacy English wordlist.
pub const ENGLISH_OLD: &str = include_str!("./monero/english_old.txt");
/// Esperanto wordlist.
pub const ESPERANTO: &str = include_str!("./monero/esperanto.txt");
/// French wordlist.
pub const FRENCH: &str = include_str!("./monero/french.txt");
/// German wordlist.
pub const GERMAN: &str = include_str!("./monero/german.txt");
/// Italian wordlist.
pub const ITALIAN: &str = include_str!("./monero/italian.txt");
/// Japanese wordlist.
pub const JAPANESE: &str = include_str!("./monero/japanese.txt");
/// Lojban wordlist.
pub const LOJBAN: &str = include_str!("./monero/lojban.txt");
/// Portuguese wordlist.
pub const PORTUGUESE: &str = include_str!("./monero/portuguese.txt");
/// Russian wordlist.
pub const RUSSIAN: &str = include_str!("./monero/russian.txt");
/// Spanish wordlist.
pub const SPANISH: &str = include_str!("./monero/spanish.txt");
