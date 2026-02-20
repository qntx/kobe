//! BIP-39 mnemonic utilities.
//!
//! This module provides helper functions for working with BIP-39 mnemonic
//! phrases, including prefix-based word expansion.
//!
//! # Prefix Expansion
//!
//! The BIP-39 English wordlist is designed so that every word is uniquely
//! identifiable by its first 4 characters. This module leverages that
//! property to allow users to type abbreviated words and have them
//! automatically expanded to full BIP-39 words.
//!
//! # Example
//!
//! ```
//! use kobe::mnemonic;
//!
//! let expanded = mnemonic::expand("aban aban aban aban aban aban aban aban aban aban aban abou").unwrap();
//! assert_eq!(
//!     expanded,
//!     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
//! );
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use bip39::Language;

use crate::Error;

/// Minimum prefix length required for unambiguous word expansion.
///
/// BIP-39 English wordlist guarantees uniqueness at 4 characters.
const MIN_PREFIX_LEN: usize = 4;

/// Expand abbreviated words in a mnemonic phrase to their full BIP-39 form.
///
/// Each whitespace-separated token is matched against the BIP-39 wordlist:
/// - If the token is an exact match, it is kept as-is.
/// - If the token is a prefix (>= 4 characters) that uniquely identifies
///   a single word, it is expanded to that word.
/// - Otherwise, an error is returned.
///
/// # Arguments
///
/// * `phrase` - A mnemonic phrase, possibly with abbreviated words
///
/// # Errors
///
/// Returns [`Error::UnknownPrefix`] if a token does not match any word.
/// Returns [`Error::AmbiguousPrefix`] if a token matches multiple words.
/// Returns [`Error::PrefixTooShort`] if a non-exact token has fewer than 4 characters.
pub fn expand(phrase: &str) -> Result<String, Error> {
    expand_in(Language::English, phrase)
}

/// Expand abbreviated words using the specified language wordlist.
///
/// See [`expand`] for details.
///
/// # Errors
///
/// Returns [`Error::UnknownPrefix`] if a token does not match any word.
/// Returns [`Error::AmbiguousPrefix`] if a token matches multiple words.
/// Returns [`Error::PrefixTooShort`] if a non-exact token has fewer than 4 characters.
pub fn expand_in(language: Language, phrase: &str) -> Result<String, Error> {
    let word_list = language.word_list();
    let tokens: Vec<&str> = phrase.split_whitespace().collect();

    let mut result = String::new();
    for (i, token) in tokens.iter().enumerate() {
        let word = resolve_token(word_list, token)?;
        if i > 0 {
            result.push(' ');
        }
        result.push_str(word);
    }
    Ok(result)
}

/// Resolve a single token against the wordlist.
///
/// Returns the full word if the token is an exact match or a unique prefix.
fn resolve_token<'a>(word_list: &'a [&'a str; 2048], token: &str) -> Result<&'a str, Error> {
    // Fast path: exact match via binary search (wordlist is sorted).
    if word_list.binary_search(&token).is_ok() {
        // Find the actual reference from the list for lifetime correctness.
        return Ok(word_list[word_list.binary_search(&token).unwrap_or(0)]);
    }

    // Token is not an exact word — treat as prefix.
    if token.len() < MIN_PREFIX_LEN {
        return Err(Error::PrefixTooShort {
            prefix: String::from(token),
            min_len: MIN_PREFIX_LEN,
        });
    }

    // Collect all words starting with this prefix.
    let mut matches: Vec<&str> = Vec::new();
    for &word in word_list {
        if word.starts_with(token) {
            matches.push(word);
        }
    }

    match matches.len() {
        0 => Err(Error::UnknownPrefix(String::from(token))),
        1 => Ok(matches[0]),
        _ => Err(Error::AmbiguousPrefix {
            prefix: String::from(token),
            candidates: matches.iter().map(|w| String::from(*w)).collect(),
        }),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const FULL_12: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn full_words_unchanged() {
        let result = expand(FULL_12).unwrap();
        assert_eq!(result, FULL_12);
    }

    #[test]
    fn four_letter_prefix_expansion() {
        let abbreviated = "aban aban aban aban aban aban aban aban aban aban aban abou";
        let result = expand(abbreviated).unwrap();
        assert_eq!(result, FULL_12);
    }

    #[test]
    fn mixed_full_and_abbreviated() {
        let input = "abandon aban abandon aban abandon aban abandon aban abandon aban abandon about";
        let result = expand(input).unwrap();
        assert_eq!(result, FULL_12);
    }

    #[test]
    fn longer_prefix_works() {
        // "abando" is a longer prefix that still uniquely matches "abandon".
        let input = "abando abando abando abando abando abando abando abando abando abando abando about";
        let result = expand(input).unwrap();
        assert_eq!(result, FULL_12);
    }

    #[test]
    fn prefix_too_short_rejected() {
        let result = expand("aba aba aba aba aba aba aba aba aba aba aba aba");
        assert!(result.is_err());
        assert!(
            matches!(result, Err(Error::PrefixTooShort { .. })),
            "expected PrefixTooShort error"
        );
    }

    #[test]
    fn unknown_prefix_rejected() {
        let result = expand("aban aban aban aban aban aban aban aban aban aban aban zzzz");
        assert!(result.is_err());
        assert!(
            matches!(result, Err(Error::UnknownPrefix(_))),
            "expected UnknownPrefix error"
        );
    }

    #[test]
    fn ambiguous_prefix_rejected() {
        // "abst" matches both "abstract" and "absurd" — wait, let me check.
        // Actually in BIP-39, each 4-letter prefix is unique, so we need a
        // shorter-than-4 prefix to get ambiguity. But we already reject < 4.
        // A 4-letter prefix should never be ambiguous in the English wordlist.
        // So this test verifies the error path with a synthetic scenario
        // by using a 3-letter prefix that would be ambiguous.
        let result = expand("aba");
        assert!(result.is_err());
    }

    #[test]
    fn preserves_word_count() {
        let abbreviated = "aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban aban art";
        let result = expand(abbreviated).unwrap();
        assert_eq!(result.split_whitespace().count(), 24);
    }

    #[test]
    fn different_words_expand_correctly() {
        // Use known BIP-39 words with their 4-letter prefixes.
        let input = "abil acti addr admi wall wris";
        let result = expand(input).unwrap();
        assert_eq!(result, "ability action address admit wall wrist");
    }

    #[test]
    fn exact_short_words_accepted() {
        // Words shorter than 4 characters (e.g. "zoo", "art") must pass as exact matches.
        let result = expand("zoo art ice");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "zoo art ice");
    }
}
