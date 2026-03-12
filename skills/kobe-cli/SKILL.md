---
name: kobe-cli
description: >-
  Generate and manage multi-chain cryptocurrency wallets using the kobe CLI tool.
  Supports Bitcoin (BTC), Ethereum (EVM), and Solana (SVM) wallet creation,
  import, and mnemonic camouflage. Use when the user asks to create wallets,
  generate addresses, derive keys, import mnemonics, import private keys, or
  encrypt/decrypt mnemonics. Supports --json flag for structured output.
---

# Kobe CLI — Multi-Chain Wallet Tool

Kobe is a Rust CLI binary (`kobe`) for generating and managing cryptocurrency wallets across Bitcoin, Ethereum, and Solana.

## Installation

```bash
cargo install kobe-cli
```

Or build locally:

```bash
cargo build --release -p kobe-cli
# binary at target/release/kobe
```

## Global Flag

All commands accept `--json` for machine-readable JSON output:

```bash
kobe --json <chain> <subcommand> [options]
```

When `--json` is used, output is a single JSON object to stdout with no color/formatting. Errors are also JSON: `{"error": "message"}`.

## Commands Reference

### Bitcoin (`kobe btc`)

| Subcommand   | Description                  |
|-------------|------------------------------|
| `new`       | Generate HD wallet           |
| `random`    | Random single-key wallet     |
| `import`    | Import from mnemonic         |
| `import-key`| Import from WIF private key  |

```bash
# Generate new Bitcoin wallet
kobe btc new --words 24 --address-type taproot --count 3

# JSON output
kobe --json btc new

# Import from mnemonic
kobe btc import --mnemonic "word1 word2 ... word12"

# Random wallet (no mnemonic)
kobe --json btc random --testnet

# Import from WIF key
kobe btc import-key --key "L..."
```

**Bitcoin-specific flags:**
- `--testnet` / `-t`: Use testnet
- `--address-type` / `-a`: `legacy`, `segwit`, `native-segwit` (default), `taproot`
- `--words` / `-w`: Mnemonic word count (12, 15, 18, 21, 24)
- `--passphrase` / `-p`: BIP-39 passphrase
- `--count` / `-c`: Number of addresses to derive
- `--qr`: Show QR code in terminal

### Ethereum (`kobe evm`)

| Subcommand   | Description                  |
|-------------|------------------------------|
| `new`       | Generate HD wallet           |
| `random`    | Random single-key wallet     |
| `import`    | Import from mnemonic         |
| `import-key`| Import from hex private key  |

```bash
# Generate new Ethereum wallet
kobe evm new --words 24 --style ledger-live --count 5

# JSON output
kobe --json evm new

# Import from mnemonic
kobe evm import --mnemonic "word1 word2 ... word12" --style standard

# Import from hex key
kobe evm import-key --key "0xabc..."
```

**EVM-specific flags:**
- `--style` / `-s`: Derivation style — `standard` (MetaMask/Trezor), `ledger-live`, `ledger-legacy`

### Solana (`kobe svm`)

| Subcommand   | Description                  |
|-------------|------------------------------|
| `new`       | Generate HD wallet           |
| `random`    | Random single-key wallet     |
| `import`    | Import from mnemonic         |
| `import-key`| Import from hex/base58 key   |

```bash
# Generate new Solana wallet
kobe svm new --words 24 --style phantom --count 3

# JSON output
kobe --json svm random

# Import from mnemonic
kobe svm import --mnemonic "word1 word2 ... word12" --style trust
```

**SVM-specific flags:**
- `--style` / `-s`: Derivation style — `standard`/`phantom`/`backpack`, `trust`/`ledger`/`keystone`, `ledger-live`, `legacy`/`old`

### Mnemonic Camouflage (`kobe mnemonic`)

Encrypt a real mnemonic into a decoy that looks like a valid BIP-39 phrase:

```bash
# Encrypt
kobe mnemonic encrypt --mnemonic "real phrase here..." --password "secret"

# Decrypt
kobe mnemonic decrypt --camouflaged "decoy phrase here..." --password "secret"

# JSON output
kobe --json mnemonic encrypt --mnemonic "real phrase here..." --password "secret"
```

## JSON Output Schema

### HD Wallet (new / import)

```json
{
  "chain": "bitcoin",
  "network": "mainnet",
  "address_type": "P2WPKH (Native SegWit)",
  "mnemonic": "word1 word2 ...",
  "passphrase_protected": false,
  "accounts": [
    {
      "index": 0,
      "derivation_path": "m/84'/0'/0'/0/0",
      "address": "bc1q...",
      "private_key": "L..."
    }
  ]
}
```

For EVM/SVM, `network` and `address_type` are omitted; `derivation_style` is included instead.

### Single Key (random / import-key)

```json
{
  "chain": "ethereum",
  "address": "0x...",
  "private_key": "0x...",
  "public_key": "0x..."
}
```

### Camouflage (encrypt / decrypt)

```json
{
  "mode": "encrypt",
  "words": 12,
  "input": "original phrase...",
  "output": "camouflaged phrase..."
}
```

### Error

```json
{
  "error": "invalid mnemonic phrase"
}
```

## Aliases

| Primary | Aliases          |
|---------|-----------------|
| `btc`   | `bitcoin`       |
| `evm`   | `eth`, `ethereum`|
| `svm`   | `sol`, `solana` |
| `mnemonic` | `mn`         |

## Agent Usage Tips

- Always use `--json` for programmatic consumption — avoids ANSI color codes and indented text
- Parse the JSON `private_key` field directly; format varies by chain (WIF for BTC, 0x-hex for EVM, base58 keypair for SVM)
- Use `--count` to batch-derive multiple addresses in one call
- Mnemonic abbreviations are auto-expanded (e.g., `ab` → `absent`, `zon` → `zone`)
- Errors in JSON mode return `{"error": "..."}` with exit code 1
