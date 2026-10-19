use bip39::Language;
use zeroize::Zeroizing;

use crate::CliResult;

/// Read exactly one line of mnemonic from stdin into a zeroizing buffer.
pub(crate) fn read_stdin_line() -> CliResult<Zeroizing<String>> {
    let mut line = Zeroizing::new(String::new());
    std::io::stdin().read_line(&mut line)?;
    if line.trim().is_empty() {
        return Err("no mnemonic on stdin".into());
    }
    let len = line.trim_end().len();
    line.truncate(len);
    Ok(line)
}

/// Expand a phrase where each token is either an exact BIP-39 English word
/// or a unique prefix of at least 4 letters.
pub(crate) fn expand_mnemonic(input: &str) -> CliResult<Zeroizing<String>> {
    let language = Language::English;
    let mut words: Vec<&'static str> = Vec::with_capacity(24);
    // Error messages name the 1-based word position, never the content.
    for (pos, raw) in input.split_whitespace().enumerate() {
        let token = Zeroizing::new(raw.to_lowercase());
        if let Some(index) = language.find_word(&token) {
            words.push(
                *language
                    .word_list()
                    .get(usize::from(index))
                    .ok_or("word index out of range")?,
            );
        } else if token.len() >= 4 {
            // BIP-39 English words are unique in their first four letters, so
            // a prefix of four or more letters matches at most one word.
            let word = language
                .word_list()
                .iter()
                .find(|w| w.starts_with(token.as_str()))
                .ok_or_else(|| {
                    format!("word {} is not a BIP-39 English word or prefix", pos + 1)
                })?;
            words.push(word);
        } else {
            return Err(format!("word {} is not a BIP-39 English word", pos + 1).into());
        }
    }
    Ok(Zeroizing::new(words.join(" ")))
}
