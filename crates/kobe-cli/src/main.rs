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
        Command::Mnemonic { words, seedqr } => {
            run_mnemonic(*words, cli.json, cli.reveal, seedqr.as_deref())
        }
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
