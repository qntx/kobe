//! Structured output types and unified rendering.
//!
//! These types serve as the single source of truth for both JSON and
//! human-readable output. Chain-specific code builds these structs,
//! then calls the shared render functions.
//!
//! **Security default:** mnemonic and private keys are omitted unless
//! the global `--reveal` flag was set when building the output.

use colored::Colorize;
use kobe::{DerivedAccount, Wallet};
use serde::Serialize;

/// Output for HD wallet operations (new, import).
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct HdWalletOutput {
    /// Blockchain identifier (bitcoin, ethereum, solana).
    pub chain: &'static str,
    /// Network name (mainnet/testnet), if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<&'static str>,
    /// Address type description (Bitcoin only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_type: Option<&'static str>,
    /// BIP-39 mnemonic phrase. Present only when `--reveal` was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
    /// Whether a BIP-39 passphrase was used.
    pub passphrase_protected: bool,
    /// Derivation path style name (EVM/SVM only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derivation_style: Option<&'static str>,
    /// Derived accounts/addresses.
    pub accounts: Vec<AccountOutput>,
}

/// A single derived account/address.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct AccountOutput {
    /// Account index in the derivation sequence.
    pub index: u32,
    /// BIP-32/44 derivation path.
    pub derivation_path: String,
    /// Blockchain address.
    pub address: String,
    /// Private key (format depends on chain). Present only when `--reveal` was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
}

/// Output for mnemonic camouflage operations.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct CamouflageOutput {
    /// Operation mode ("encrypt" or "decrypt").
    pub mode: &'static str,
    /// Mnemonic word count.
    pub words: usize,
    /// Input mnemonic (original for encrypt, camouflaged for decrypt).
    /// Present only when `--reveal` was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<String>,
    /// Output mnemonic (camouflaged for encrypt, recovered for decrypt).
    /// Present only when `--reveal` was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
}

impl CamouflageOutput {
    /// Build camouflage output, redacting phrases unless `reveal` is true.
    #[must_use]
    pub fn new(mode: &'static str, words: usize, input: String, output: String, reveal: bool) -> Self {
        Self {
            mode,
            words,
            input: reveal.then_some(input),
            output: reveal.then_some(output),
        }
    }
}

impl HdWalletOutput {
    /// Build HD output with optional network / address-type / style metadata.
    ///
    /// When `reveal` is false, `mnemonic` is omitted from the struct.
    #[must_use]
    pub fn new(
        chain: &'static str,
        wallet: &Wallet,
        network: Option<&'static str>,
        address_type: Option<&'static str>,
        derivation_style: Option<&'static str>,
        accounts: Vec<AccountOutput>,
        reveal: bool,
    ) -> Self {
        Self {
            chain,
            network,
            address_type,
            mnemonic: reveal.then(|| wallet.mnemonic().to_owned()),
            passphrase_protected: wallet.has_passphrase(),
            derivation_style,
            accounts,
        }
    }

    /// Build output for a simple chain (no network, no address type, no derivation style).
    #[must_use]
    pub fn simple(
        chain: &'static str,
        wallet: &Wallet,
        accounts: &[DerivedAccount],
        reveal: bool,
    ) -> Self {
        Self::new(
            chain,
            wallet,
            None,
            None,
            None,
            accounts
                .iter()
                .enumerate()
                .map(|(i, a)| AccountOutput::from_derived(i, a, reveal))
                .collect(),
            reveal,
        )
    }
}

impl AccountOutput {
    /// Build from a [`DerivedAccount`] with a sequential index.
    #[must_use]
    pub fn from_derived(index: usize, account: &DerivedAccount, reveal: bool) -> Self {
        Self::from_parts(
            index,
            account.path(),
            account.address(),
            account.private_key_hex().as_str(),
            reveal,
        )
    }

    /// Build with an explicit private-key string (WIF, base58 keypair, `0x…` hex, …).
    ///
    /// The key is stored only when `reveal` is true.
    #[must_use]
    pub fn from_parts(
        index: usize,
        derivation_path: &str,
        address: &str,
        private_key: &str,
        reveal: bool,
    ) -> Self {
        Self {
            index: u32::try_from(index).unwrap_or(u32::MAX),
            derivation_path: derivation_path.to_owned(),
            address: address.to_owned(),
            private_key: reveal.then(|| private_key.to_owned()),
        }
    }
}

/// Structured error output for JSON mode.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct ErrorOutput {
    /// Error message.
    pub error: String,
}

/// Render an HD wallet result as JSON or colored text.
///
/// # Errors
///
/// Returns an error if JSON serialization fails.
#[rustfmt::skip]
pub fn render_hd_wallet(
    out: &HdWalletOutput,
    json: bool,
    show_qr: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if json {
        return Ok(print_json(out)?);
    }

    println!();
    if let Some(network) = out.network {
        println!("      {}      {}", "Network".cyan().bold(), network);
    }
    if let Some(addr_type) = out.address_type {
        println!("      {} {}", "Address Type".cyan().bold(), addr_type);
    }
    if let Some(ref mnemonic) = out.mnemonic {
        println!("      {}     {}", "Mnemonic".cyan().bold(), mnemonic);
    } else {
        println!(
            "      {}     {}",
            "Mnemonic".cyan().bold(),
            "(hidden; pass -r / --reveal)".dimmed()
        );
    }
    if out.passphrase_protected {
        println!("      {}   {}", "Passphrase".cyan().bold(), "(set)".dimmed());
    }
    if let Some(style) = out.derivation_style {
        println!("      {}        {}", "Style".cyan().bold(), style.dimmed());
    }
    println!();

    let multi = out.accounts.len() > 1;
    for (i, acct) in out.accounts.iter().enumerate() {
        if multi {
            println!("      {}        {}", "Index".cyan().bold(), format!("[{}]", acct.index).dimmed());
        }
        println!("      {}         {}", "Path".cyan().bold(), acct.derivation_path);
        println!("      {}      {}", "Address".cyan().bold(), acct.address.green());
        if let Some(ref pk) = acct.private_key {
            println!("      {}  {}", "Private Key".cyan().bold(), pk);
        } else {
            println!(
                "      {}  {}",
                "Private Key".cyan().bold(),
                "(hidden; pass -r / --reveal)".dimmed()
            );
        }
        if show_qr {
            crate::qr::render_to_terminal(&acct.address);
        }
        if i < out.accounts.len() - 1 {
            println!();
        }
    }
    println!();
    Ok(())
}

/// Render a camouflage result as JSON or colored text.
///
/// # Errors
///
/// Returns an error if JSON serialization fails.
#[rustfmt::skip]
pub fn render_camouflage(
    out: &CamouflageOutput,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if json {
        return Ok(print_json(out)?);
    }

    let mode_label = if out.mode == "encrypt" { "Encrypt" } else { "Decrypt" };
    let (in_label, out_label) = if out.mode == "encrypt" {
        ("Original", "Camouflaged")
    } else {
        ("Camouflaged", "Recovered")
    };

    println!();
    println!("      {}         {}", "Mode".cyan().bold(), mode_label);
    println!("      {}        {} words", "Words".cyan().bold(), out.words);
    let hidden = "(hidden; pass -r / --reveal)";
    match (&out.input, &out.output) {
        (Some(input), Some(output)) if out.mode == "encrypt" => {
            println!("      {}     {}", in_label.cyan().bold(), input);
            println!("      {}  {}", out_label.cyan().bold(), output.green());
        }
        (Some(input), Some(output)) => {
            println!("      {}  {}", in_label.cyan().bold(), input);
            println!("      {}    {}", out_label.cyan().bold(), output.green());
        }
        _ => {
            println!("      {}     {}", in_label.cyan().bold(), hidden.dimmed());
            println!("      {}  {}", out_label.cyan().bold(), hidden.dimmed());
        }
    }
    println!();
    Ok(())
}

/// Serialize a value as pretty-printed JSON and write to stdout.
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn print_json<T: Serialize>(value: &T) -> Result<(), serde_json::Error> {
    let json = serde_json::to_string_pretty(value)?;
    println!("{json}");
    Ok(())
}
