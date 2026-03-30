<!-- markdownlint-disable MD033 MD041 MD036 -->

# Kobe

[![CI][ci-badge]][ci-url]
[![License][license-badge]][license-url]
[![Rust][rust-badge]][rust-url]

[ci-badge]: https://github.com/qntx/kobe/actions/workflows/rust.yml/badge.svg
[ci-url]: https://github.com/qntx/kobe/actions/workflows/rust.yml
[license-badge]: https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg
[license-url]: LICENSE-MIT
[rust-badge]: https://img.shields.io/badge/rust-edition%202024-orange.svg
[rust-url]: https://doc.rust-lang.org/edition-guide/

**Modular, `no_std`-compatible Rust toolkit for multi-chain HD wallet derivation — 10 chains, one seed, zero hand-written cryptography.**

Kobe derives standards-compliant addresses for Bitcoin, Ethereum, Solana, Cosmos, Tron, Sui, TON, Filecoin, and Spark from a single BIP-39 mnemonic. All library crates compile under `no_std + alloc` and zeroize sensitive material on drop.

## Crates

| Crate | | Description |
| --- | --- | --- |
| **[`kobe`](kobe/)** | [![crates.io][kobe-crate]][kobe-crate-url] [![docs.rs][kobe-doc]][kobe-doc-url] | Umbrella crate — re-exports `kobe-core` + feature-gated chain crates |
| **[`kobe-core`](kobe-core/)** | [![crates.io][kobe-core-crate]][kobe-core-crate-url] [![docs.rs][kobe-core-doc]][kobe-core-doc-url] | Core library — BIP-39/32, SLIP-10, Wallet, `no_std` + `alloc` |
| **[`kobe-btc`](kobe-btc/)** | [![crates.io][kobe-btc-crate]][kobe-btc-crate-url] [![docs.rs][kobe-btc-doc]][kobe-btc-doc-url] | Bitcoin — P2PKH, P2SH-P2WPKH, P2WPKH, P2TR |
| **[`kobe-evm`](kobe-evm/)** | [![crates.io][kobe-evm-crate]][kobe-evm-crate-url] [![docs.rs][kobe-evm-doc]][kobe-evm-doc-url] | Ethereum — MetaMask / Ledger Live / Ledger Legacy styles |
| **[`kobe-svm`](kobe-svm/)** | [![crates.io][kobe-svm-crate]][kobe-svm-crate-url] [![docs.rs][kobe-svm-doc]][kobe-svm-doc-url] | Solana — Phantom / Trust / Ledger Live styles |
| **[`kobe-cosmos`](kobe-cosmos/)** | [![crates.io][kobe-cosmos-crate]][kobe-cosmos-crate-url] [![docs.rs][kobe-cosmos-doc]][kobe-cosmos-doc-url] | Cosmos — configurable HRP and coin type |
| **[`kobe-tron`](kobe-tron/)** | [![crates.io][kobe-tron-crate]][kobe-tron-crate-url] [![docs.rs][kobe-tron-doc]][kobe-tron-doc-url] | Tron — base58check addresses |
| **[`kobe-sui`](kobe-sui/)** | [![crates.io][kobe-sui-crate]][kobe-sui-crate-url] [![docs.rs][kobe-sui-doc]][kobe-sui-doc-url] | Sui — SLIP-10 Ed25519 + BLAKE2b-256 |
| **[`kobe-ton`](kobe-ton/)** | [![crates.io][kobe-ton-crate]][kobe-ton-crate-url] [![docs.rs][kobe-ton-doc]][kobe-ton-doc-url] | TON — wallet v5r1, Tonkeeper / Ledger Live styles |
| **[`kobe-fil`](kobe-fil/)** | [![crates.io][kobe-fil-crate]][kobe-fil-crate-url] [![docs.rs][kobe-fil-doc]][kobe-fil-doc-url] | Filecoin — f1 secp256k1 addresses |
| **[`kobe-spark`](kobe-spark/)** | [![crates.io][kobe-spark-crate]][kobe-spark-crate-url] [![docs.rs][kobe-spark-doc]][kobe-spark-doc-url] | Spark — Lightning-compatible addresses |
| **[`kobe-cli`](kobe-cli/)** | [![crates.io][kobe-cli-crate]][kobe-cli-crate-url] | CLI — generate, import, derive across all chains |

[kobe-crate]: https://img.shields.io/crates/v/kobe.svg
[kobe-crate-url]: https://crates.io/crates/kobe
[kobe-core-crate]: https://img.shields.io/crates/v/kobe-core.svg
[kobe-core-crate-url]: https://crates.io/crates/kobe-core
[kobe-btc-crate]: https://img.shields.io/crates/v/kobe-btc.svg
[kobe-btc-crate-url]: https://crates.io/crates/kobe-btc
[kobe-evm-crate]: https://img.shields.io/crates/v/kobe-evm.svg
[kobe-evm-crate-url]: https://crates.io/crates/kobe-evm
[kobe-svm-crate]: https://img.shields.io/crates/v/kobe-svm.svg
[kobe-svm-crate-url]: https://crates.io/crates/kobe-svm
[kobe-cosmos-crate]: https://img.shields.io/crates/v/kobe-cosmos.svg
[kobe-cosmos-crate-url]: https://crates.io/crates/kobe-cosmos
[kobe-tron-crate]: https://img.shields.io/crates/v/kobe-tron.svg
[kobe-tron-crate-url]: https://crates.io/crates/kobe-tron
[kobe-sui-crate]: https://img.shields.io/crates/v/kobe-sui.svg
[kobe-sui-crate-url]: https://crates.io/crates/kobe-sui
[kobe-ton-crate]: https://img.shields.io/crates/v/kobe-ton.svg
[kobe-ton-crate-url]: https://crates.io/crates/kobe-ton
[kobe-fil-crate]: https://img.shields.io/crates/v/kobe-fil.svg
[kobe-fil-crate-url]: https://crates.io/crates/kobe-fil
[kobe-spark-crate]: https://img.shields.io/crates/v/kobe-spark.svg
[kobe-spark-crate-url]: https://crates.io/crates/kobe-spark
[kobe-cli-crate]: https://img.shields.io/crates/v/kobe-cli.svg
[kobe-cli-crate-url]: https://crates.io/crates/kobe-cli
[kobe-doc]: https://img.shields.io/docsrs/kobe.svg
[kobe-doc-url]: https://docs.rs/kobe
[kobe-core-doc]: https://img.shields.io/docsrs/kobe-core.svg
[kobe-core-doc-url]: https://docs.rs/kobe-core
[kobe-btc-doc]: https://img.shields.io/docsrs/kobe-btc.svg
[kobe-btc-doc-url]: https://docs.rs/kobe-btc
[kobe-evm-doc]: https://img.shields.io/docsrs/kobe-evm.svg
[kobe-evm-doc-url]: https://docs.rs/kobe-evm
[kobe-svm-doc]: https://img.shields.io/docsrs/kobe-svm.svg
[kobe-svm-doc-url]: https://docs.rs/kobe-svm
[kobe-cosmos-doc]: https://img.shields.io/docsrs/kobe-cosmos.svg
[kobe-cosmos-doc-url]: https://docs.rs/kobe-cosmos
[kobe-tron-doc]: https://img.shields.io/docsrs/kobe-tron.svg
[kobe-tron-doc-url]: https://docs.rs/kobe-tron
[kobe-sui-doc]: https://img.shields.io/docsrs/kobe-sui.svg
[kobe-sui-doc-url]: https://docs.rs/kobe-sui
[kobe-ton-doc]: https://img.shields.io/docsrs/kobe-ton.svg
[kobe-ton-doc-url]: https://docs.rs/kobe-ton
[kobe-fil-doc]: https://img.shields.io/docsrs/kobe-fil.svg
[kobe-fil-doc-url]: https://docs.rs/kobe-fil
[kobe-spark-doc]: https://img.shields.io/docsrs/kobe-spark.svg
[kobe-spark-doc-url]: https://docs.rs/kobe-spark

## Quick Start

### Install the CLI

**Shell** (macOS / Linux):

```sh
curl -fsSL https://sh.qntx.fun/kobe | sh
```

**PowerShell** (Windows):

```powershell
irm https://sh.qntx.fun/kobe/ps | iex
```

Or via Cargo:

```bash
cargo install kobe-cli
```

### CLI Usage

```bash
# Generate wallets
kobe btc new                              # Bitcoin (Native SegWit)
kobe btc new -a taproot -w 24 -c 5        # 5 Taproot addresses, 24 words
kobe evm new                              # Ethereum (MetaMask-compatible)
kobe evm new --style ledger-live -c 3    # Ledger Live style, 3 accounts
kobe svm new                              # Solana (Phantom-compatible)
kobe cosmos new                           # Cosmos Hub
kobe sui new                              # Sui
kobe ton new                              # TON

# Import from mnemonic
kobe evm import -m "abandon abandon ... about"

# JSON output (for scripts / agents)
kobe evm new --json
```

### Library Usage

```rust
use kobe::{Wallet, Derive};
use kobe::evm::Deriver;  // or kobe::btc, kobe::svm, kobe::cosmos, ...

// Import from mnemonic
let wallet = Wallet::from_mnemonic(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    None,  // optional passphrase
)?;

// Derive addresses
let eth = kobe::evm::Deriver::new(&wallet).derive(0)?;
let btc = kobe::btc::Deriver::new(&wallet, kobe::btc::Network::Mainnet)?.derive(0)?;
let sol = kobe::svm::Deriver::new(&wallet).derive(0)?;

println!("ETH: {}", eth.address);  // 0x9858EfFD232B4033E47d90003D41EC34EcaEda94
println!("BTC: {}", btc.address);  // bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
println!("SOL: {}", sol.address);  // HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk
```

```rust
// Generate new wallet
let wallet = Wallet::generate(12, None)?;  // 12-word mnemonic
println!("Mnemonic: {}", wallet.mnemonic());
```

## Design

- **10 chains** — Bitcoin, Ethereum, Solana, Cosmos, Tron, Sui, TON, Filecoin, Spark — one BIP-39 seed
- **HD standards** — BIP-32, BIP-39, BIP-44/49/84/86, SLIP-10
- **Derivation styles** — Standard, Ledger Live, Ledger Legacy, Trust, Phantom, Backpack
- **`no_std` + `alloc`** — All library crates compile without `std`; embedded / WASM ready
- **Zeroizing** — Private keys, seeds, and intermediate material wrapped in `Zeroizing<T>`
- **Shared infrastructure** — SLIP-10 Ed25519 and BIP-32 secp256k1 derivation in `kobe-core`
- **KAT-verified** — Every chain has Known Answer Tests cross-verified with Python
- **Strict linting** — Clippy `pedantic` + `nursery` + `correctness` (deny), zero warnings

## Feature Flags

The umbrella `kobe` crate uses feature flags to select chains:

| Feature | Chains |
| --- | --- |
| `btc` | Bitcoin (default) |
| `evm` | Ethereum (default) |
| `svm` | Solana (default) |
| `cosmos` | Cosmos Hub, Osmosis, Terra, etc. |
| `tron` | Tron |
| `sui` | Sui |
| `ton` | TON |
| `fil` | Filecoin |
| `spark` | Spark (Lightning) |
| `all-chains` | All of the above |

Core features on `kobe` / `kobe-core`:

| Feature | Description |
| --- | --- |
| `std` | Full std support (default) |
| `alloc` | Heap allocation for `no_std` |
| `rand` | Random mnemonic generation via OS entropy |
| `camouflage` | Mnemonic camouflage (XOR + PBKDF2) |

## Mnemonic Camouflage

The `camouflage` feature provides entropy-layer XOR encryption that transforms a real BIP-39 mnemonic into a **different but fully valid** BIP-39 mnemonic. The camouflaged mnemonic is indistinguishable from any ordinary mnemonic — it even generates a real (empty) wallet.

**How it works:**

```text
Real Mnemonic → Entropy (128–256 bit) → XOR(PBKDF2(password)) → New Entropy → Decoy Mnemonic
```

1. The real mnemonic is decoded into its raw entropy (128, 160, 192, 224, or 256 bits).
2. A key of matching length is derived from the password via **PBKDF2-HMAC-SHA256** (600,000 iterations).
3. The entropy is **XORed** with the derived key to produce new entropy.
4. The new entropy is re-encoded as a valid BIP-39 mnemonic with a correct checksum.

Decryption is the same operation — XOR is its own inverse.

**Supported word counts:** 12, 15, 18, 21, and 24 words.

**Security properties:**

| Property | Detail |
| --- | --- |
| **Valid output** | Decoy mnemonic passes all BIP-39 validation and generates a real wallet |
| **Stateless** | No files, databases, or extra data — just the password |
| **Deterministic** | Same input + password always produces the same output |
| **Password-bound** | Security strength equals the password entropy |
| **Brute-force resistant** | PBKDF2 with 600K iterations (OWASP 2023 recommendation) |

> **Note:** This is _not_ the BIP-39 passphrase (25th word). BIP-39 passphrases alter seed derivation; camouflage alters the mnemonic entropy itself.

### Camouflage Library API

```rust
use kobe::camouflage;

// Encrypt (camouflage)
let decoy = camouflage::encrypt("real mnemonic ...", "password")?;

// Decrypt (recover)
let original = camouflage::decrypt(&decoy, "password")?;
```

### Camouflage CLI

```bash
kobe mnemonic encrypt -m "abandon abandon ... art" -p "strong-password"
kobe mnemonic decrypt -c "decoy abandon ... xyz"   -p "strong-password"
```

## Security

This library has **not** been independently audited. Use at your own risk.

- Private keys and seeds use [`zeroize`](https://docs.rs/zeroize) for secure memory cleanup
- No key material is logged or persisted
- Random generation uses OS-provided CSPRNG via [`getrandom`](https://docs.rs/getrandom)
- Secp256k1 contexts are cached to avoid repeated allocations
- Environment variable manipulation is disallowed at the lint level

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project shall be dual-licensed as above, without any additional terms or conditions.

---

<div align="center">

A **[QNTX](https://qntx.fun)** open-source project.

<a href="https://qntx.fun"><img alt="QNTX" width="369" src="https://raw.githubusercontent.com/qntx/.github/main/profile/qntx-banner.svg" /></a>

<!--prettier-ignore-->
Code is law. We write both.

</div>
