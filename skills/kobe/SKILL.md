---
name: kobe
description: >-
  Multi-chain cryptocurrency wallet CLI tool for generating, importing, and
  managing HD wallets across 10 chains: Bitcoin, Ethereum, Solana, Cosmos, Tron,
  Sui, TON, Filecoin, and Spark. Use when the user asks to create wallets,
  generate addresses, derive keys, import mnemonics, or perform any
  cryptocurrency wallet operation. Supports JSON output via --json flag.
---

# Kobe CLI — Multi-Chain HD Wallet Tool

`kobe` is a single binary CLI for generating and managing cryptocurrency wallets across **10 chains**: Bitcoin, Ethereum, Solana, Cosmos, Tron, Sui, TON, Filecoin, and Spark. It supports BIP-39 mnemonic generation, HD key derivation (BIP-32/44/49/84/86, SLIP-10), multiple derivation styles for hardware wallet compatibility, and mnemonic camouflage encryption.

## Installation

### One-line install (recommended)

**macOS / Linux:**

```sh
curl -fsSL https://sh.qntx.fun/kobe | sh
```

**Windows (PowerShell):**

```powershell
irm https://sh.qntx.fun/kobe/ps | iex
```

These scripts download the latest pre-built binary from GitHub Releases and add it to PATH. No Rust toolchain required.

### Verify installation

```sh
kobe --version
```

## CLI Structure

```text
kobe [--json] <chain> <subcommand> [options]
```

The `--json` flag is **global** and must appear **before** the chain subcommand. When set, all output (including errors) is a single JSON object on stdout with no ANSI colors.

### Chain subcommands and aliases

| Chain    | Primary    | Aliases           |
| -------- | ---------- | ----------------- |
| Bitcoin  | `btc`      | `bitcoin`         |
| Ethereum | `evm`      | `eth`, `ethereum` |
| Solana   | `svm`      | `sol`, `solana`   |
| Cosmos   | `cosmos`   | `atom`            |
| Tron     | `tron`     | `trx`             |
| Sui      | `sui`      | —                 |
| TON      | `ton`      | —                 |
| Filecoin | `fil`      | `filecoin`        |
| Spark    | `spark`    | —                 |
| Mnemonic | `mnemonic` | `mn`              |

### Subcommands per chain

All chains support:

| Subcommand | Description                                     |
| ---------- | ----------------------------------------------- |
| `new`      | Generate a new HD wallet with a random mnemonic |
| `import`   | Import an HD wallet from an existing mnemonic   |

The `mnemonic` command supports:

| Subcommand | Description                                          |
| ---------- | ---------------------------------------------------- |
| `encrypt`  | Camouflage a mnemonic into a valid decoy mnemonic    |
| `decrypt`  | Recover the original mnemonic from a camouflaged one |

## Common Flags

| Flag           | Short | Scope           | Description                                              |
| -------------- | ----- | --------------- | -------------------------------------------------------- |
| `--json`       |       | Global          | JSON output mode (must come before chain subcommand)     |
| `--words`      | `-w`  | `new`           | Mnemonic word count: 12, 15, 18, 21, or 24 (default: 12) |
| `--passphrase` | `-p`  | `new`, `import` | Optional BIP-39 passphrase for seed derivation           |
| `--count`      | `-c`  | `new`, `import` | Number of addresses to derive (default: 1)               |
| `--qr`         |       | All             | Display QR code in terminal for each address             |
| `--mnemonic`   | `-m`  | `import`        | BIP-39 mnemonic phrase (supports prefix abbreviation)    |

### Bitcoin-specific flags

| Flag             | Short | Values                                         | Default         |
| ---------------- | ----- | ---------------------------------------------- | --------------- |
| `--testnet`      | `-t`  | (flag)                                         | mainnet         |
| `--address-type` | `-a`  | `legacy`, `segwit`, `native-segwit`, `taproot` | `native-segwit` |

### EVM-specific flags

| Flag      | Short | Values                                     | Default    |
| --------- | ----- | ------------------------------------------ | ---------- |
| `--style` | `-s`  | `standard`, `ledger-live`, `ledger-legacy` | `standard` |

### SVM-specific flags

| Flag      | Short | Values                                       | Default    |
| --------- | ----- | -------------------------------------------- | ---------- |
| `--style` | `-s`  | `standard`, `trust`, `ledger-live`, `legacy` | `standard` |

Aliases: `phantom`/`backpack` → `standard`, `ledger`/`keystone` → `trust`, `old` → `legacy`

### Cosmos-specific flags

| Flag          | Short | Description                                      | Default   |
| ------------- | ----- | ------------------------------------------------ | --------- |
| `--hrp`       |       | Bech32 human-readable prefix                     | `cosmos`  |
| `--coin-type` |       | BIP-44 coin type (118=Cosmos, 330=Terra, etc.)   | `118`     |

## Usage Examples

### Bitcoin

```bash
# Generate a new Native SegWit wallet (default)
kobe btc new

# Generate 5 Taproot addresses with a 24-word mnemonic
kobe btc new -w 24 -a taproot -c 5

# Generate on testnet
kobe btc new --testnet

# Import from mnemonic (supports abbreviated prefixes)
kobe btc import -m "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# JSON output for programmatic use
kobe --json btc new
```

### Ethereum

```bash
# Generate a new wallet (MetaMask-compatible Standard path)
kobe evm new

# Ledger Live style, 3 accounts
kobe evm new --style ledger-live -c 3

# Import from mnemonic
kobe evm import -m "abandon abandon ..." --style standard

# JSON output
kobe --json evm new
```

### Solana

```bash
# Generate a new wallet (Phantom-compatible Standard path)
kobe svm new

# Trust Wallet style, 3 accounts
kobe svm new --style trust -c 3

# Import from mnemonic (phantom is alias for standard)
kobe svm import -m "abandon abandon ..." --style phantom

# JSON output
kobe --json svm new
```

### Cosmos

```bash
# Generate a Cosmos Hub wallet
kobe cosmos new

# Osmosis (different HRP)
kobe cosmos new --hrp osmo

# Terra (different coin type)
kobe cosmos new --hrp terra --coin-type 330

# Import from mnemonic
kobe cosmos import -m "abandon abandon ..." --hrp cosmos
```

### Sui

```bash
# Generate a Sui wallet
kobe sui new

# Import from mnemonic
kobe sui import -m "abandon abandon ..."
```

### TON

```bash
# Generate a TON wallet
kobe ton new

# Import from mnemonic
kobe ton import -m "abandon abandon ..."
```

### Other Chains

```bash
# Tron
kobe tron new

# Filecoin
kobe fil new

# Spark (Bitcoin L2)
kobe spark new
```

### Mnemonic Camouflage

```bash
# Encrypt a real mnemonic into a valid-looking decoy
kobe mnemonic encrypt -m "real phrase here ..." -p "strong-password"

# Recover the original from the decoy
kobe mnemonic decrypt -c "decoy phrase here ..." -p "strong-password"

# JSON output
kobe --json mnemonic encrypt -m "real phrase ..." -p "secret"
```

## JSON Output Schemas

Always use `--json` for programmatic consumption. It disables ANSI colors and outputs a single JSON object.

### HD Wallet (`new` / `import`)

```json
{
  "chain": "bitcoin",
  "network": "mainnet",
  "address_type": "P2WPKH (Native SegWit)",
  "mnemonic": "word1 word2 ... word12",
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

For EVM/SVM: `network` and `address_type` are omitted; `derivation_style` is included instead.

### Camouflage (`encrypt` / `decrypt`)

```json
{
  "mode": "encrypt",
  "words": 12,
  "input": "original phrase ...",
  "output": "camouflaged phrase ..."
}
```

### Error

All errors in JSON mode return exit code 1 with:

```json
{
  "error": "invalid mnemonic phrase"
}
```

## Private Key Formats by Chain

| Chain    | Format in `private_key` field                            |
| -------- | -------------------------------------------------------- |
| Bitcoin  | WIF (Wallet Import Format), e.g. `L1a...` or `5H...`     |
| Ethereum | `0x`-prefixed 64-char hex string                         |
| Solana   | Base58-encoded 64-byte keypair (secret 32B + public 32B) |
| Cosmos   | 64-char hex string                                       |
| Tron     | 64-char hex string                                       |
| Sui      | 64-char hex string (Ed25519 secret key)                  |
| TON      | 64-char hex string (Ed25519 secret key)                  |
| Filecoin | 64-char hex string                                       |
| Spark    | 64-char hex string (compressed pubkey also provided)     |

## Derivation Path Reference

### Bitcoin (BIP-32/44/49/84/86)

| Address Type           | Path Pattern        | Prefix    |
| ---------------------- | ------------------- | --------- |
| P2PKH (Legacy)         | `m/44'/0'/0'/0/{i}` | `1...`    |
| P2SH-P2WPKH (SegWit)   | `m/49'/0'/0'/0/{i}` | `3...`    |
| P2WPKH (Native SegWit) | `m/84'/0'/0'/0/{i}` | `bc1q...` |
| P2TR (Taproot)         | `m/86'/0'/0'/0/{i}` | `bc1p...` |

### Ethereum (BIP-44)

| Style         | Path Pattern         | Compatible Wallets |
| ------------- | -------------------- | ------------------ |
| Standard      | `m/44'/60'/0'/0/{i}` | MetaMask, Trezor   |
| Ledger Live   | `m/44'/60'/{i}'/0/0` | Ledger Live        |
| Ledger Legacy | `m/44'/60'/0'/{i}`   | MEW, MyCrypto      |

### Solana (SLIP-10 Ed25519)

| Style       | Path Pattern            | Compatible Wallets              |
| ----------- | ----------------------- | ------------------------------- |
| Standard    | `m/44'/501'/{i}'/0'`    | Phantom, Backpack, Solflare     |
| Trust       | `m/44'/501'/{i}'`       | Trust Wallet, Ledger, Keystone  |
| Ledger Live | `m/44'/501'/{i}'/0'/0'` | Ledger Live                     |
| Legacy      | `m/501'/{i}'/0'/0'`     | Old Phantom/Sollet (deprecated) |

### Cosmos (BIP-44)

| Chain       | Path Pattern          | Coin Type |
| ----------- | --------------------- | --------- |
| Cosmos Hub  | `m/44'/118'/0'/0/{i}` | 118       |
| Osmosis     | `m/44'/118'/0'/0/{i}` | 118       |
| Terra       | `m/44'/330'/0'/0/{i}` | 330       |

### Sui (SLIP-10 Ed25519)

| Path Pattern              | Notes                   |
| ------------------------- | ----------------------- |
| `m/44'/784'/{i}'/0'/0'`   | All hardened components |

### TON (SLIP-10 Ed25519)

| Path Pattern      | Notes                    |
| ----------------- | ------------------------ |
| `m/44'/607'/{i}'` | Tonkeeper-compatible     |

### Tron (BIP-44)

| Path Pattern          | Notes                    |
| --------------------- | ------------------------ |
| `m/44'/195'/0'/0/{i}` | Same as Ethereum format  |

### Filecoin (BIP-44)

| Path Pattern          | Address Prefix |
| --------------------- | -------------- |
| `m/44'/461'/0'/0/{i}` | `f1...`        |

### Spark (BIP-84)

| Path Pattern          | Notes                         |
| --------------------- | ----------------------------- |
| `m/84'/0'/0'/0/{i}`   | Same as Bitcoin Native SegWit |

## Agent Best Practices

1. **Always use `--json`** for programmatic consumption to avoid ANSI escape codes.
2. **Parse `private_key` by chain**: WIF for BTC, base58 keypair for SVM, hex for all others.
3. **Use `--count`** to batch-derive multiple addresses in one call.
4. **Mnemonic abbreviations** are auto-expanded: each BIP-39 word is uniquely identifiable by its first 4 characters (e.g., `aban` → `abandon`, `abou` → `about`).
5. **Errors** in JSON mode return `{"error": "..."}` with exit code 1.
6. **`--json` placement**: The flag must appear before the chain subcommand: `kobe --json btc new`, not `kobe btc --json new`.
7. **Camouflage** is not the BIP-39 passphrase (25th word). It XOR-encrypts the mnemonic entropy itself using PBKDF2, producing a different but valid mnemonic.
