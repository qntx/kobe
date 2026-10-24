#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    missing_docs,
    reason = "the CLI binary legitimately prints to stdout/stderr and its public items need no docs"
)]
//! kobe — pure offline HD wallet generator CLI.

mod cli;
mod help;
mod mnemonic;
mod qr;
mod render;
mod seedqr;
mod target;

use std::process::ExitCode;

use clap::Parser;
use kobe::{ChildIndex, Style, Wallet, WordCount};
use serde_json::json;
use std::io::{IsTerminal, Write as _};
use zeroize::Zeroizing;

use cli::{Cli, Command};

pub(crate) type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let json = argv.iter().any(|a| a == "--json");
    match Cli::try_parse_from(&argv) {
        Err(e) if e.use_stderr() => fail(&e.to_string(), json),
        Err(e) => {
            let _ignored = write!(anstream::stdout(), "{e}");
            ExitCode::SUCCESS
        }
        Ok(cli) => match run(&cli) {
            Ok(output) => {
                let _ignored = writeln!(anstream::stdout(), "{output}");
                ExitCode::SUCCESS
            }
            Err(e) => fail(&e.to_string(), json),
        },
    }
}

fn fail(message: &str, json: bool) -> ExitCode {
    if json {
        let _ignored = writeln!(anstream::stdout(), "{}", render::error_json(message));
    } else {
        let _ignored = writeln!(
            anstream::stderr(),
            "{} {}",
            render::error_prefix(),
            message.trim()
        );
    }
    ExitCode::FAILURE
}

fn run(cli: &Cli) -> CliResult<String> {
    match &cli.command {
        Command::Mnemonic {
            action,
            words,
            seedqr,
        } => match action {
            Some(cli::MnemonicAction::Encrypt(a)) => run_crypt(true, a, cli.json, cli.reveal),
            Some(cli::MnemonicAction::Decrypt(a)) => run_crypt(false, a, cli.json, cli.reveal),
            None => run_mnemonic(*words, cli.json, cli.reveal, seedqr.as_deref()),
        },
        command => {
            let Some(spec) = command.spec() else {
                return Err("missing command".into());
            };
            run_chain(&spec, cli.json, cli.reveal)
        }
    }
}

fn run_mnemonic(
    words: WordCount,
    json: bool,
    reveal: bool,
    seedqr: Option<&str>,
) -> CliResult<String> {
    let wallet = Wallet::random(words, "")?;
    if json {
        let v = json!({ "mnemonic": wallet.mnemonic(), "words": words.words() });
        return Ok(serde_json::to_string_pretty(&v).unwrap_or_else(|_| v.to_string()));
    }
    // --seedqr requires --reveal: it puts the secret on screen.
    if let Some(kind) = seedqr {
        if !reveal {
            return Err("--seedqr requires --reveal".into());
        }
        let kind = seedqr::SeedQrKind::parse(kind)?;
        let code = seedqr::encode(&wallet, kind)?;
        let warn = render::warn("! The SeedQR encodes your full mnemonic — keep it secret.");
        return Ok(format!(
            "{warn}
{}",
            qr::matrix_to_text_pub(&code)
        ));
    }
    // Pipe: bare mnemonic (D4). TTY: labelled block.
    if !std::io::stdout().is_terminal() {
        return Ok(wallet.mnemonic().to_owned());
    }
    let mut out = String::from('\n');
    out.push_str(&render::block_label("Mnemonic", wallet.mnemonic()));
    out.push_str(&render::block_label("Words", &words.words().to_string()));
    out.push('\n');
    Ok(out)
}

fn run_chain(spec: &target::ChainSpec<'_>, json: bool, reveal: bool) -> CliResult<String> {
    let chain = spec.chain.as_ref();
    let args = spec.args;
    let generating = args.mnemonic.is_none();
    let passphrase = if args.passphrase == "-" {
        mnemonic::prompt_passphrase(generating)?
    } else {
        Zeroizing::new(args.passphrase.clone())
    };
    let wallet = if let Some(source) = &args.mnemonic {
        let raw = if source == "-" {
            mnemonic::read_stdin_line()?
        } else {
            Zeroizing::new(source.clone())
        };
        let phrase = mnemonic::expand_mnemonic(&raw)?;
        Wallet::from_mnemonic(&phrase, &passphrase)?
    } else {
        Wallet::random(args.words, &passphrase)?
    };

    let style = match &args.path {
        Some(template) => Style::new("custom", template.clone(), ""),
        None => target::select_style(chain, args.style.as_ref())?,
    };

    let iterates = style.has_index();
    let start = args.index.unwrap_or(style.start);
    let count = if iterates { args.count.unwrap_or(1) } else { 1 };
    if count == 0 {
        return Err("count must be at least 1".into());
    }
    let last = u64::from(start) + u64::from(count) - 1;
    if last > u64::from(ChildIndex::MAX) {
        return Err(format!(
            "index range {start}..={last} exceeds the maximum {}",
            ChildIndex::MAX
        )
        .into());
    }

    let mut accounts = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
    for offset in 0..count {
        // Bounded by `last <= ChildIndex::MAX` above: cannot overflow.
        let index = start + offset;
        let path = style.path(index)?;
        accounts.push((index, chain.derive(&wallet, &path)?));
    }

    Ok(if json {
        render::json_output(spec.id, &spec.options, &style, &wallet, &accounts, reveal)
    } else {
        render::human_output(
            spec.id,
            &spec.options,
            &style,
            &wallet,
            &accounts,
            reveal,
            args.qr,
        )
    })
}

fn run_crypt(encrypt: bool, args: &cli::CryptArgs, json: bool, reveal: bool) -> CliResult<String> {
    if encrypt {
        return run_encrypt(args, json, reveal);
    }
    run_decrypt(args, json, reveal)
}

fn crypt_wallet_and_password(
    encrypt: bool,
    args: &cli::CryptArgs,
) -> CliResult<(Wallet, usize, Zeroizing<String>, Zeroizing<String>)> {
    if args.mnemonic == "-" && args.password_stdin {
        return Err("-m - and --password-stdin both read stdin".into());
    }
    let raw = if args.mnemonic == "-" {
        mnemonic::read_stdin_line()?
    } else {
        Zeroizing::new(args.mnemonic.clone())
    };
    let phrase = mnemonic::expand_mnemonic(&raw)?;
    let wallet = Wallet::from_mnemonic(&phrase, "")?;
    let words = phrase.split_whitespace().count();

    let password = if args.password_stdin {
        mnemonic::password_from_stdin()?
    } else {
        mnemonic::prompt_password(encrypt)?
    };
    if password.is_empty() {
        return Err("password must not be empty".into());
    }

    Ok((wallet, words, phrase, password))
}

fn strength_word(score: u8) -> &'static str {
    ["very weak", "weak", "fair", "good", "strong"]
        .get(usize::from(score.min(4)))
        .copied()
        .unwrap_or("unknown")
}

fn run_encrypt(args: &cli::CryptArgs, json: bool, reveal: bool) -> CliResult<String> {
    let (wallet, words, phrase, password) = crypt_wallet_and_password(true, args)?;
    let mut warnings = String::new();
    {
        let score = u8::from(zxcvbn::zxcvbn(&password, &[]).score());
        let label = strength_word(score);
        if score < 3 && !args.allow_weak_password {
            return Err(format!(
                "password too weak (zxcvbn {score}/4); pass --allow-weak-password to override"
            )
            .into());
        }
        let camouflaged = kobe::camouflage::encrypt(&wallet, &password)?;
        // Verify the round trip before printing anything.
        let cam_wallet = Wallet::from_mnemonic(&camouflaged, "")?;
        let back = kobe::camouflage::decrypt(&cam_wallet, &password)?;
        if back.as_str() != phrase.as_str() {
            return Err("round-trip verification failed".into());
        }
        let fp_hex = hex4(wallet.fingerprint()?);
        warnings.push_str(&render::warn(
            "! The camouflaged phrase is itself a valid (empty) wallet.",
        ));
        warnings.push('\n');
        warnings.push_str(&render::warn(
            "! Only this password recovers the original; it cannot be reset.",
        ));
        warnings.push('\n');
        warnings.push_str(&render::warn("! Never reuse a password across mnemonics."));
        if json {
            let mut map = serde_json::Map::new();
            map.insert("mode".into(), json!("encrypt"));
            map.insert("words".into(), json!(words));
            map.insert("strength".into(), json!(format!("{label} ({score}/4)")));
            if reveal {
                map.insert("phrase".into(), json!(camouflaged.as_str()));
            }
            map.insert("fingerprint".into(), json!(fp_hex));
            let v = serde_json::Value::Object(map);
            return Ok(serde_json::to_string_pretty(&v).unwrap_or_else(|_| v.to_string()));
        }
        let mut out = render::block(&[
            ("Mode", render::Val::Plain(String::from("encrypt"))),
            ("Words", render::Val::Plain(words.to_string())),
            (
                "Strength",
                render::Val::Plain(format!("{label} (zxcvbn {score}/4)")),
            ),
            (
                "Camouflaged",
                if reveal {
                    render::Val::Green(camouflaged.as_str().to_owned())
                } else {
                    render::Val::Dim(render::HIDDEN.to_owned())
                },
            ),
            (
                "Fingerprint",
                render::Val::Plain(format!("{fp_hex} (original wallet — note it separately)")),
            ),
            ("Verified", render::Val::Plain("round-trip ok".to_owned())),
        ]);
        out.push_str(&warnings);
        Ok(out)
    }
}

fn run_decrypt(args: &cli::CryptArgs, json: bool, reveal: bool) -> CliResult<String> {
    let (wallet, words, _phrase, password) = crypt_wallet_and_password(false, args)?;
    let mut warnings = String::new();
    {
        if !kobe::camouflage::is_nfc(&password) {
            warnings.push_str(&render::warn(
                "! Password is not Unicode NFC; using it byte-for-byte.",
            ));
            warnings.push('\n');
        }
        let recovered = kobe::camouflage::decrypt(&wallet, &password)?;
        let rec_wallet = Wallet::from_mnemonic(&recovered, "")?;
        let fp_hex = hex4(rec_wallet.fingerprint()?);
        warnings.push_str(&render::warn(
            "! Check the fingerprint against your records before revealing.",
        ));
        if json {
            let mut map = serde_json::Map::new();
            map.insert("mode".into(), json!("decrypt"));
            map.insert("words".into(), json!(words));
            if reveal {
                map.insert("phrase".into(), json!(recovered.as_str()));
            }
            map.insert("fingerprint".into(), json!(fp_hex));
            let v = serde_json::Value::Object(map);
            return Ok(serde_json::to_string_pretty(&v).unwrap_or_else(|_| v.to_string()));
        }
        let mut out = render::block(&[
            ("Mode", render::Val::Plain(String::from("decrypt"))),
            ("Words", render::Val::Plain(words.to_string())),
            (
                "Recovered",
                if reveal {
                    render::Val::Green(recovered.as_str().to_owned())
                } else {
                    render::Val::Dim(render::HIDDEN.to_owned())
                },
            ),
            ("Fingerprint", render::Val::Plain(fp_hex)),
        ]);
        out.push_str(&warnings);
        Ok(out)
    }
}

fn hex4(fp: [u8; 4]) -> String {
    use std::fmt::Write as _;
    fp.iter().fold(String::with_capacity(8), |mut s, b| {
        let _h = write!(s, "{b:02x}");
        s
    })
}
