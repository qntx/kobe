//! Structured output types and unified rendering.
//!
//! These types serve as the single source of truth for both JSON and
//! human-readable output. Chain-specific code builds these structs,
//! then calls the shared render functions.

use colored::Colorize;
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
    /// BIP-39 mnemonic phrase.
    pub mnemonic: String,
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
    /// Private key (format depends on chain: WIF for BTC, hex for EVM, base58 for SVM).
    pub private_key: String,
}

/// Output for random/import-key operations (no mnemonic).
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct SingleKeyOutput {
    /// Blockchain identifier.
    pub chain: &'static str,
    /// Network name, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<&'static str>,
    /// Address type description (Bitcoin only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_type: Option<&'static str>,
    /// Blockchain address.
    pub address: String,
    /// Private key (format depends on chain).
    pub private_key: String,
    /// Public key in hex format.
    pub public_key: String,
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
    pub input: String,
    /// Output mnemonic (camouflaged for encrypt, recovered for decrypt).
    pub output: String,
}

/// Structured error output for JSON mode.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct ErrorOutput {
    /// Error message.
    pub error: String,
}

// ---------------------------------------------------------------------------
// Unified render functions
// ---------------------------------------------------------------------------

/// Render an HD wallet result as JSON or colored text.
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
    println!("      {}     {}", "Mnemonic".cyan().bold(), out.mnemonic);
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
        println!("      {}  {}", "Private Key".cyan().bold(), acct.private_key);
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

/// Render a single-key wallet result as JSON or colored text.
#[rustfmt::skip]
pub fn render_single_key(
    out: &SingleKeyOutput,
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
    println!("      {}      {}", "Address".cyan().bold(), out.address.green());
    println!("      {}  {}", "Private Key".cyan().bold(), out.private_key);
    println!("      {}   {}", "Public Key".cyan().bold(), out.public_key.dimmed());
    if show_qr {
        crate::qr::render_to_terminal(&out.address);
    }
    println!();
    Ok(())
}

/// Render a camouflage result as JSON or colored text.
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
    if out.mode == "encrypt" {
        println!("      {}     {}", in_label.cyan().bold(), out.input);
        println!("      {}  {}", out_label.cyan().bold(), out.output.green());
    } else {
        println!("      {}  {}", in_label.cyan().bold(), out.input);
        println!("      {}    {}", out_label.cyan().bold(), out.output.green());
    }
    println!();
    Ok(())
}

/// Serialize a value as pretty-printed JSON and write to stdout.
pub fn print_json<T: Serialize>(value: &T) -> Result<(), serde_json::Error> {
    let json = serde_json::to_string_pretty(value)?;
    println!("{json}");
    Ok(())
}
