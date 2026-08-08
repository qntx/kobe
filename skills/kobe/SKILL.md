---
name: kobe
description: >-
  Multi-chain cryptocurrency wallet CLI tool for generating, importing, and
  managing HD wallets across 13 chains: Aptos, Bitcoin, Ethereum, Solana, Cosmos,
  Tron, Sui, TON, Filecoin, Spark, XRP Ledger, Nostr, and Casper. Use when the user
  asks to create wallets, generate addresses, derive keys, import mnemonics,
  produce NIP-19 `npub` / `nsec` identities, Casper account-hash addresses, or
  perform any cryptocurrency wallet operation. Supports JSON output via --json flag.
---

# Kobe CLI — Multi-Chain HD Wallet Tool

`kobe` is a single binary CLI for generating and managing cryptocurrency wallets across **13 chains**: Aptos, Bitcoin, Ethereum, Solana, Cosmos, Tron, Sui, TON, Filecoin, Spark, XRP Ledger, Nostr, and Casper. It supports BIP-39 mnemonic generation, HD key derivation (BIP-32/44/49/84/86, SLIP-10, NIP-06), multiple derivation styles for hardware wallet compatibility, NIP-19 bech32 output for Nostr, Casper AccountHash addresses, and mnemonic camouflage encryption.

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

### Self-upgrade (sh.qntx.fun installs)

```sh
kobe upgrade              # install latest if newer (`update` is an alias)
kobe upgrade --check      # report only
kobe upgrade --force      # reinstall even when up to date
```

Re-runs the same installer as above. Cargo-installed binaries are **not**
overwritten; the command prints a `cargo install kobe-cli --force` hint instead.

## CLI Structure

```text
kobe [--json] [-r|--reveal] <command> [options]
```

The `--json` and `-r` / `--reveal` flags are **global**. When `--json` is set, all output (including errors) is a single JSON object on stdout with no ANSI colors.

**Secrets default to hidden:** mnemonic and private keys are omitted unless `-r` / `--reveal` is passed.

### Chain subcommands and aliases

| Chain      | Primary    | Aliases           |
| ---------- | ---------- | ----------------- |
| Aptos      | `aptos`    | `apt`             |
| Bitcoin    | `btc`      | `bitcoin`         |
| Ethereum   | `evm`      | `eth`, `ethereum` |
| Solana     | `svm`      | `sol`, `solana`   |
| Cosmos     | `cosmos`   | `atom`            |
| Tron       | `tron`     | `trx`             |
| Sui        | `sui`      | —                 |
| TON        | `ton`      | —                 |
| Filecoin   | `fil`      | `filecoin`        |
| Spark      | `spark`    | —                 |
| XRP Ledger | `xrpl`     | `xrp`, `ripple`   |
| Nostr      | `nostr`    | —                 |
| Casper     | `casper`   | `cspr`            |
| Mnemonic   | `mnemonic` | `mn`              |
| Upgrade    | `upgrade`  | `update`          |

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
| `--json`       |       | Global          | JSON output mode                                         |
| `--reveal`     | `-r`  | Global          | Include mnemonic and private keys (default: hidden)      |
| `--words`      | `-w`  | `new`           | Mnemonic word count: 12, 15, 18, 21, or 24 (default: 12) |
| `--passphrase` | `-p`  | `new`, `import` | Optional BIP-39 passphrase for seed derivation           |
| `--count`      | `-c`  | `new`, `import` | Number of addresses to derive (default: 1)               |
| `--qr`         |       | All             | Display QR code in terminal for each address             |
| `--mnemonic`   | `-m`  | `import`        | BIP-39 mnemonic phrase (supports prefix abbreviation)    |
| `--check`      |       | `upgrade`       | Only report whether a newer release exists               |
| `--force`      |       | `upgrade`       | Re-run installer even when already latest                |

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

| Flag          | Short | Description                                    | Default  |
| ------------- | ----- | ---------------------------------------------- | -------- |
| `--hrp`       |       | Bech32 human-readable prefix                   | `cosmos` |
| `--coin-type` |       | BIP-44 coin type (118=Cosmos, 330=Terra, etc.) | `118`    |

### TON-specific flags

All four axes are independent. Key material is unaffected by `--testnet`,
`--bounceable`, and `--workchain`; only the human-readable address changes.

| Flag            | Short | Values                                                         | Default    |
| --------------- | ----- | -------------------------------------------------------------- | ---------- |
| `--testnet`     | `-t`  | (flag) flips the address tag bit and walletId                  | mainnet    |
| `--bounceable`  | `-b`  | (flag) emit `EQ…`/`kQ…` instead of `UQ…`/`0Q…`                 | off        |
| `--workchain`   |       | Signed 8-bit workchain id (`0` basechain, `-1` masterchain)    | `0`        |
| `--style`       | `-s`  | `standard` (alias `tonkeeper`), `ledger-live` (alias `live`)   | `standard` |

### Spark-specific flags

| Flag        | Short | Values                                             | Default   |
| ----------- | ----- | -------------------------------------------------- | --------- |
| `--network` | `-n`  | `mainnet`, `testnet`, `signet`, `regtest`, `local` | `mainnet` |

### Casper-specific flags

| Flag     | Short | Values                                        | Default     |
| -------- | ----- | --------------------------------------------- | ----------- |
| `--algo` |       | `secp256k1` (aliases `secp`, `ecdsa`), `ed25519` (aliases `ed`, `eddsa`) | `secp256k1` |

Default path is Ledger secp256k1 `m/44'/506'/0'/0/{i}`. Ed25519 uses
`m/44'/506'/0'/0'/{i}'`. Address is `account-hash-` + 64 hex.

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
# Generate a TON wallet (mainnet, non-bounceable, basechain, Tonkeeper path)
kobe ton new

# Mainnet bounceable (EQ...) for smart-contract destinations
kobe ton new --bounceable

# Testnet non-bounceable (0Q...)
kobe ton new --testnet

# Masterchain (workchain -1) testnet bounceable (kQ...)
kobe ton new --testnet --bounceable --workchain -1

# Ledger Live derivation path
kobe ton new --style ledger-live

# Import from mnemonic
kobe ton import -m "abandon abandon ..."
```

### Aptos

```bash
# Generate an Aptos wallet
kobe aptos new

# Import from mnemonic
kobe aptos import -m "abandon abandon ..."
```

### Other Chains

```bash
# Tron
kobe tron new

# Filecoin
kobe fil new

# Spark (Bitcoin L2) — mainnet by default (spark1...)
kobe spark new

# Spark on a specific network
kobe spark new --network testnet   # sparkt1...
kobe spark new --network signet    # sparks1...
kobe spark new --network regtest   # sparkrt1...
kobe spark new --network local     # sparkl1...

# XRP Ledger
kobe xrpl new

# Casper (default secp256k1 Ledger path → account-hash-…)
kobe casper new
kobe casper new --algo ed25519 -c 3
```

### Nostr

Nostr uses NIP-06 derivation (`m/44'/1237'/<account>'/0/0`) and NIP-19
bech32 output. Each account exposes both the raw 64-char hex private key
and the `nsec1…` form, plus the `npub1…` address alongside the 32-byte
x-only public key.

```bash
# Generate a new Nostr identity (default: 1 account)
kobe nostr new

# Generate 3 distinct identities (NIP-06 iterates the *account* level)
kobe nostr new -c 3

# Import from an existing mnemonic
kobe nostr import -m "abandon abandon ... about"

# JSON output — exposes both `private_key` (hex) and NIP-19 forms
kobe --json nostr new
```

### Mnemonic Camouflage

Phrases are **hidden unless** `-r` / `--reveal`. Prefer stdin for the phrase:

```bash
# Encrypt (output hidden without -r)
echo "real phrase here ..." | kobe mnemonic encrypt -m - -p "strong-password" -r

# Recover
echo "decoy phrase here ..." | kobe mnemonic decrypt -c - -p "strong-password" -r

# JSON with secrets
echo "real phrase ..." | kobe --json -r mnemonic encrypt -m - -p "secret"
```

## JSON Output Schemas

Always use `--json` for programmatic consumption. It disables ANSI colors and outputs a single JSON object.

### HD Wallet (`new` / `import`)

With `-r` / `--reveal` (secrets included):

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

Without `--reveal`, `mnemonic` and each account's `private_key` are omitted.
For EVM/SVM: `network` and `address_type` are omitted; `derivation_style` is included instead.

### Upgrade (`upgrade` / `update`)

```json
{
  "current": "3.1.0",
  "latest": "3.1.0",
  "update_available": false,
  "action": "up_to_date",
  "message": "kobe 3.0.0 is up to date"
}
```

### Camouflage (`encrypt` / `decrypt`)

With `-r` / `--reveal`:

```json
{
  "mode": "encrypt",
  "words": 12,
  "input": "original phrase ...",
  "output": "camouflaged phrase ..."
}
```

Without `--reveal`, `input` and `output` are omitted.

### Error

All errors in JSON mode return exit code 1 with:

```json
{
  "error": "invalid mnemonic phrase"
}
```

## Private Key Formats by Chain

| Chain      | Format in `private_key` field                                            |
| ---------- | ------------------------------------------------------------------------ |
| Aptos      | 64-char hex string (Ed25519 secret key)                                  |
| Bitcoin    | WIF (Wallet Import Format), e.g. `L1a...` or `5H...`                     |
| Ethereum   | `0x`-prefixed 64-char hex string                                         |
| Solana     | Base58-encoded 64-byte keypair (secret 32B + public 32B)                 |
| Cosmos     | 64-char hex string                                                       |
| Tron       | 64-char hex string                                                       |
| Sui        | 64-char hex string (Ed25519 secret key)                                  |
| TON        | 64-char hex string (Ed25519 secret key)                                  |
| Filecoin   | 64-char hex string                                                       |
| Spark      | 64-char hex string (compressed pubkey also provided)                     |
| XRP Ledger | 64-char hex string                                                       |
| Nostr      | NIP-19 bech32 `nsec1…` (64-char hex also available; address is `npub1…`) |
| Casper     | 64-char hex string (secp256k1 or Ed25519 secret; address is `account-hash-…`) |

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

| Chain      | Path Pattern          | Coin Type |
| ---------- | --------------------- | --------- |
| Cosmos Hub | `m/44'/118'/0'/0/{i}` | 118       |
| Osmosis    | `m/44'/118'/0'/0/{i}` | 118       |
| Terra      | `m/44'/330'/0'/0/{i}` | 330       |

### Aptos (SLIP-10 Ed25519)

| Path Pattern            | Notes                      |
| ----------------------- | -------------------------- |
| `m/44'/637'/{i}'/0'/0'` | SHA3-256(0x00 \|\| pubkey) |

### Sui (SLIP-10 Ed25519)

| Path Pattern            | Notes                   |
| ----------------------- | ----------------------- |
| `m/44'/784'/{i}'/0'/0'` | All hardened components |

### TON (SLIP-10 Ed25519)

| Style         | Path Pattern              | Compatible wallets                    |
| ------------- | ------------------------- | ------------------------------------- |
| `standard`    | `m/44'/607'/{i}'`         | Tonkeeper, `MyTonWallet`, Trust Wallet |
| `ledger-live` | `m/44'/607'/{i}'/0'/0'`   | Ledger Live                           |

Wallet contract: v5r1. Address format is controlled by `--testnet`,
`--bounceable`, and `--workchain` flags (independent of key derivation).

### Tron (BIP-44)

| Path Pattern          | Notes                   |
| --------------------- | ----------------------- |
| `m/44'/195'/0'/0/{i}` | Same as Ethereum format |

### Filecoin (BIP-44)

| Path Pattern          | Address Prefix |
| --------------------- | -------------- |
| `m/44'/461'/0'/0/{i}` | `f1...`        |

### Spark (BIP-32 secp256k1, Spark-specific purpose)

| Path Pattern            | Notes                                                        |
| ----------------------- | ------------------------------------------------------------ |
| `m/8797555'/{i}'/0'`    | Purpose `8797555` = `SHA-256("spark")` truncated (per spec). |

Address: Bech32m-encoded compressed identity public key wrapped in a
2-byte pseudo-protobuf header. HRP depends on `--network`: `spark` (mainnet),
`sparkt` (testnet), `sparks` (signet), `sparkrt` (regtest), `sparkl` (local).

### XRP Ledger (BIP-44)

| Path Pattern          | Address Format     |
| --------------------- | ------------------ |
| `m/44'/144'/0'/0/{i}` | Base58Check `r...` |

### Nostr (NIP-06)

| Path Pattern                 | Notes                                                              |
| ---------------------------- | ------------------------------------------------------------------ |
| `m/44'/1237'/{account}'/0/0` | NIP-06: `{account}` is the `-c` index; pubkey is x-only / `npub1…` |

### Casper (SLIP-44 coin type 506)

| Algorithm   | Path Pattern              | Notes |
| ----------- | ------------------------- | ----- |
| `secp256k1` | `m/44'/506'/0'/0/{i}`     | Default (Ledger / casper-cli secp) |
| `ed25519`   | `m/44'/506'/0'/0'/{i}'`   | SLIP-10 full-hardened |

Address: BLAKE2b-256 of `algorithm_name || 0x00 || raw_pubkey` formatted as
`account-hash-` + 64 lowercase hex (per `casper-types`).

## Agent Best Practices

1. **Always use `--json`** for programmatic consumption to avoid ANSI escape codes.
2. **Pass `-r` / `--reveal` when secrets are required**; default output omits mnemonic and private keys.
3. **Parse `private_key` by chain**: WIF for BTC, base58 keypair for SVM, hex for all others.
4. **Use `--count`** to batch-derive multiple addresses in one call.
5. **Mnemonic abbreviations** are auto-expanded: each BIP-39 word is uniquely identifiable by its first 4 characters (e.g., `aban` → `abandon`, `abou` → `about`).
6. **Errors** in JSON mode return `{"error": "..."}` with exit code 1.
7. **Camouflage** is not the BIP-39 passphrase (25th word). It XOR-encrypts the mnemonic entropy itself using PBKDF2, producing a different but valid mnemonic.
8. **Self-upgrade** for script installs: `kobe upgrade` (alias `update`); cargo installs need `cargo install kobe-cli --force`.
