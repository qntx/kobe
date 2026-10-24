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

/// Read a BIP-39 passphrase without echo. Generating a new wallet requires
/// typing it twice. `reader` is injectable for tests; the production call
/// uses `rpassword` on the controlling TTY (prompt on stderr).
pub(crate) fn prompt_passphrase_with(
    confirm: bool,
    mut reader: impl FnMut(&str) -> CliResult<String>,
) -> CliResult<Zeroizing<String>> {
    let first = Zeroizing::new(reader("Passphrase: ")?);
    if first.is_empty() {
        return Err("empty passphrase".into());
    }
    if confirm {
        let again = Zeroizing::new(reader("Confirm: ")?);
        if *first != *again {
            return Err("passphrases do not match".into());
        }
    }
    Ok(first)
}

pub(crate) fn prompt_passphrase(generating: bool) -> CliResult<Zeroizing<String>> {
    prompt_passphrase_with(generating, |prompt| {
        rpassword::prompt_password(prompt)
            .map_err(|e| format!("cannot read passphrase: {e}").into())
    })
}

/// Hidden prompt for a camouflage password: `Password:` and (encrypt)
/// `Confirm:`. Fails clearly without a TTY.
pub(crate) fn prompt_password(confirm: bool) -> CliResult<Zeroizing<String>> {
    let read = |prompt: &str| -> CliResult<String> {
        rpassword::prompt_password(prompt).map_err(|e| format!("cannot read password: {e}").into())
    };
    let first = Zeroizing::new(read("Password: ")?);
    if first.is_empty() {
        return Err("empty password".into());
    }
    if confirm {
        let again = Zeroizing::new(read("Confirm: ")?);
        if *first != *again {
            return Err("passwords do not match".into());
        }
    }
    Ok(first)
}

/// Read the password from stdin (`--password-stdin`): one line, strips
/// exactly one trailing newline (`\n` or `\r\n`), nothing else.
pub(crate) fn password_from_stdin() -> CliResult<Zeroizing<String>> {
    let mut raw = Zeroizing::new(String::new());
    std::io::stdin().read_line(&mut raw)?;
    if raw.is_empty() {
        return Err("no password on stdin".into());
    }
    let trimmed = raw
        .strip_suffix("\r\n")
        .or_else(|| raw.strip_suffix('\n'))
        .unwrap_or(raw.as_str())
        .to_owned();
    Ok(Zeroizing::new(trimmed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_reads_once_when_importing() {
        let p = prompt_passphrase_with(false, |_| Ok("hunter2".to_owned())).expect("read");
        assert_eq!(p.as_str(), "hunter2");
    }

    #[test]
    fn prompt_confirms_when_generating() {
        let mut calls = 0u8;
        let p = prompt_passphrase_with(true, |prompt| {
            calls += 1;
            assert!(prompt.contains("Passphrase") || prompt.contains("Confirm"));
            Ok("same".to_owned())
        });
        assert!(p.is_ok());
        assert_eq!(calls, 2);
    }

    #[test]
    fn prompt_rejects_mismatch_and_empty() {
        let mut n = 0;
        let r = prompt_passphrase_with(true, |_| {
            n += 1;
            Ok(if n == 1 {
                "a".to_owned()
            } else {
                "b".to_owned()
            })
        });
        assert!(r.is_err());
        let empty = prompt_passphrase_with(false, |_| Ok(String::new()));
        assert!(empty.is_err());
    }
}
