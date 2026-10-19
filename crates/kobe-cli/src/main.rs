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
mod render;
mod target;

use std::process::ExitCode;

use clap::Parser;
use kobe::{ChildIndex, Style, Wallet, WordCount};
use serde_json::json;
use zeroize::Zeroizing;

use cli::{Cli, Command};

pub(crate) type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let json = argv.iter().any(|a| a == "--json");
    match Cli::try_parse_from(&argv) {
        Err(e) if e.use_stderr() => fail(&e.to_string(), json),
        Err(e) => {
            print!("{e}");
            ExitCode::SUCCESS
        }
        Ok(cli) => match run(&cli) {
            Ok(output) => {
                println!("{output}");
                ExitCode::SUCCESS
            }
            Err(e) => fail(&e.to_string(), json),
        },
    }
}

fn fail(message: &str, json: bool) -> ExitCode {
    if json {
        println!("{}", json!({ "error": message.trim() }));
    } else {
        eprintln!("error: {}", message.trim());
    }
    ExitCode::FAILURE
}

fn run(cli: &Cli) -> CliResult<String> {
    match &cli.command {
        Command::Mnemonic { words } => run_mnemonic(*words, cli.json),
        command => {
            let Some(spec) = command.spec() else {
                return Err("missing command".into());
            };
            run_chain(&spec, cli.json, cli.reveal)
        }
    }
}

fn run_mnemonic(words: WordCount, json: bool) -> CliResult<String> {
    let wallet = Wallet::random(words, "")?;
    Ok(if json {
        json!({ "mnemonic": wallet.mnemonic(), "words": words.words() }).to_string()
    } else {
        wallet.mnemonic().to_owned()
    })
}

fn run_chain(spec: &target::ChainSpec<'_>, json: bool, reveal: bool) -> CliResult<String> {
    let chain = spec.chain.as_ref();
    let args = spec.args;
    let passphrase = Zeroizing::new(args.passphrase.clone());
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
        render::human_output(spec.id, &spec.options, &style, &wallet, &accounts, reveal)
    })
}
