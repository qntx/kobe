# kobe

[![CI][ci-badge]][ci-url]
[![License][license-badge]][license-url]
[![Rust][rust-badge]][rust-url]

[ci-badge]: https://github.com/qntx/kobe/actions/workflows/rust.yml/badge.svg
[ci-url]: https://github.com/qntx/kobe/actions/workflows/rust.yml
[license-badge]: https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg
[license-url]: LICENSE-MIT
[rust-badge]: https://img.shields.io/badge/rust-edition%202024-orange.svg
[rust-url]: https://doc.rust-lang.org/edition-guide/

**Modular, `no_std`-compatible Rust toolkit for HD wallet derivation — BIP39 mnemonic management, multi-chain address generation, and a batteries-included CLI.**

kobe provides a unified [`Wallet`] seed from a single mnemonic, then delegates to per-chain crates for standards-compliant key derivation (BIP32/44/49/84/86 for Bitcoin, BIP-44 for Ethereum, SLIP-10 for Solana). All library crates compile under `no_std + alloc` and zeroize sensitive material on drop.

## Crates

| Kobe Crate | | Description |
| --- | --- | --- |
| **[`kobe`](kobe/)** | [![crates.io][kobe-crate]][kobe-crate-url] [![docs.rs][kobe-doc]][kobe-doc-url] | Core library — BIP39 mnemonic, seed derivation, `no_std` wallet type |
| **[`kobe-btc`](kobe-btc/)** | [![crates.io][kobe-btc-crate]][kobe-btc-crate-url] [![docs.rs][kobe-btc-doc]][kobe-btc-doc-url] | Bitcoin — P2PKH, P2SH-P2WPKH, P2WPKH, P2TR address derivation |
| **[`kobe-evm`](kobe-evm/)** | [![crates.io][kobe-evm-crate]][kobe-evm-crate-url] [![docs.rs][kobe-evm-doc]][kobe-evm-doc-url] | Ethereum (EVM) — BIP-44 derivation, MetaMask / Ledger Live / Ledger Legacy styles |
| **[`kobe-svm`](kobe-svm/)** | [![crates.io][kobe-svm-crate]][kobe-svm-crate-url] [![docs.rs][kobe-svm-doc]][kobe-svm-doc-url] | Solana (SVM) — SLIP-10 Ed25519, Phantom / Trust / Ledger Live styles |
| **[`kobe-cli`](kobe-cli/)** | [![crates.io][kobe-cli-crate]][kobe-cli-crate-url] | CLI tool — generate, import, and derive wallets across all supported chains |

[kobe-crate]: https://img.shields.io/crates/v/kobe.svg
[kobe-crate-url]: https://crates.io/crates/kobe
[kobe-btc-crate]: https://img.shields.io/crates/v/kobe-btc.svg
[kobe-btc-crate-url]: https://crates.io/crates/kobe-btc
[kobe-evm-crate]: https://img.shields.io/crates/v/kobe-evm.svg
[kobe-evm-crate-url]: https://crates.io/crates/kobe-evm
[kobe-svm-crate]: https://img.shields.io/crates/v/kobe-svm.svg
[kobe-svm-crate-url]: https://crates.io/crates/kobe-svm
[kobe-cli-crate]: https://img.shields.io/crates/v/kobe-cli.svg
[kobe-cli-crate-url]: https://crates.io/crates/kobe-cli
[kobe-doc]: https://img.shields.io/docsrs/kobe.svg
[kobe-doc-url]: https://docs.rs/kobe
[kobe-btc-doc]: https://img.shields.io/docsrs/kobe-btc.svg
[kobe-btc-doc-url]: https://docs.rs/kobe-btc
[kobe-evm-doc]: https://img.shields.io/docsrs/kobe-evm.svg
[kobe-evm-doc-url]: https://docs.rs/kobe-evm
[kobe-svm-doc]: https://img.shields.io/docsrs/kobe-svm.svg
[kobe-svm-doc-url]: https://docs.rs/kobe-svm

Planned: **`kobe-sui`** (Sui), **`kobe-xmr`** (Monero), **`kobe-zec`** (Zcash).

## Quick Start

### Derive an Ethereum Address (Library)

```rust
use kobe::Wallet;
use kobe_evm::{DerivationStyle, Deriver};

let wallet = Wallet::from_mnemonic(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    None,
)?;

let deriver = Deriver::new(wallet.seed(), DerivationStyle::Standard);
let addr = deriver.derive(0)?;

println!("Address: {}", addr.address);  // 0x9858EfFD232B4033E47d90003D41EC34EcaEda94
```

### Generate a Bitcoin Wallet (Library)

```rust
use kobe::Wallet;
use kobe_btc::{AddressType, Deriver, Network};

let wallet = Wallet::generate(12, None)?;

let deriver = Deriver::new(wallet.seed(), AddressType::P2wpkh, Network::Mainnet);
let addr = deriver.derive(0)?;

println!("Address: {}", addr.address);
println!("Path:    {}", addr.path);
```

### CLI Usage

```bash
# Generate a new Bitcoin wallet (Native SegWit)
kobe btc new

# Generate 5 Taproot addresses with a 24-word mnemonic
kobe btc new --words 24 --address-type taproot --count 5

# Generate a new Ethereum wallet (Ledger Live style)
kobe eth new --derivation-style ledger-live --count 3

# Generate a new Solana wallet (Phantom style)
kobe sol new --derivation-style standard

# Import from an existing mnemonic
kobe eth import --mnemonic "abandon abandon ... about"

# Camouflage a mnemonic (encrypt into a decoy mnemonic)
kobe mnemonic encrypt --mnemonic "real mnemonic ..." --password "strong-password"

# Recover the original mnemonic from a camouflaged one
kobe mnemonic decrypt --camouflaged "decoy mnemonic ..." --password "strong-password"
```

Install via Cargo:

```bash
cargo install kobe-cli
```

## Design

- **Multi-chain** — Bitcoin (4 address types), Ethereum, Solana — from one BIP39 seed
- **HD standards** — BIP32, BIP39, BIP44 / 49 / 84 / 86, SLIP-10
- **Derivation styles** — Standard, Ledger Live, Ledger Legacy, Trust Wallet, Legacy (Solana)
- **`no_std` + `alloc`** — All library crates compile without `std`; suitable for embedded / WASM
- **Zeroizing** — Private keys and seeds wrapped in `Zeroizing<T>` — cleared on drop
- **CSPRNG** — Random generation via OS-provided `rand_core::OsRng`
- **Linting** — `pedantic` + `nursery` + `correctness` (deny) — strict Clippy across workspace
- **Edition** — Rust **2024** — RPITIT, `no_std` ergonomics

## Feature Flags

Each crate uses feature flags to minimize compile-time dependencies:

| Crate | `std` | `alloc` | `rand` | `rand_core` | `camouflage` |
| --- | --- | --- | --- | --- | --- |
| `kobe` | Full std support (default) | Heap allocation for `no_std` | Random mnemonic via OS RNG | Custom RNG for `no_std` | Mnemonic camouflage (XOR + PBKDF2) |
| `kobe-btc` | Full std support (default) | Heap allocation for `no_std` | Random key generation | — | — |
| `kobe-evm` | Full std support (default) | Heap allocation for `no_std` | Random key generation | — | — |
| `kobe-svm` | Full std support (default) | Heap allocation for `no_std` | Ed25519 key generation | — | — |

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
- No key material is logged or persisted by the library
- Random generation uses OS-provided CSPRNG via `rand_core::OsRng`
- Camouflage operations zeroize all intermediate entropy and key material on drop
- Environment variable manipulation is disallowed at the lint level

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project shall be dual-licensed as above, without any additional terms or conditions.
