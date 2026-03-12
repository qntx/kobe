//! Structured output types for JSON serialization.
//!
//! These types provide machine-readable JSON output when the `--json` flag
//! is used, enabling agent and programmatic consumption of wallet data.

use serde::Serialize;

/// Output for HD wallet operations (new, import).
#[derive(Debug, Serialize)]
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
pub struct ErrorOutput {
    /// Error message.
    pub error: String,
}

/// Serialize a value as pretty-printed JSON and write to stdout.
pub fn print_json<T: Serialize>(value: &T) -> Result<(), serde_json::Error> {
    let json = serde_json::to_string_pretty(value)?;
    println!("{json}");
    Ok(())
}
