# Kobe

[![Crates.io][crates-badge]][crates-url]
[![Docs.rs][docs-badge]][docs-url]
[![CI][ci-badge]][ci-url]
[![License][license-badge]][license-url]
[![Rust][rust-badge]][rust-url]

[crates-badge]: https://img.shields.io/crates/v/kobe.svg
[crates-url]: https://crates.io/crates/kobe
[docs-badge]: https://img.shields.io/docsrs/kobe.svg
[docs-url]: https://docs.rs/kobe
[ci-badge]: https://github.com/qntx/kobe/actions/workflows/ci.yml/badge.svg
[ci-url]: https://github.com/qntx/kobe/actions/workflows/ci.yml
[license-badge]: https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg
[license-url]: LICENSE-MIT
[rust-badge]: https://img.shields.io/badge/rust-edition%202024-orange.svg
[rust-url]: https://doc.rust-lang.org/edition-guide/

**`no_std`-compatible Rust toolkit for multi-chain HD wallet derivation — one BIP-39 seed, twelve networks, zero hand-written cryptography, cross-implementation KATs.**

Kobe derives standards-compliant accounts and addresses for Aptos, Bitcoin, Ethereum, Solana, Cosmos, Tron, Sui, TON, Filecoin, Spark, XRP Ledger, and Nostr (NIP-06 / NIP-19) from a single BIP-39 mnemonic. It layers thin wrappers around [`bip39`](https://docs.rs/bip39), [`bip32`](https://docs.rs/bip32), [`bitcoin`](https://docs.rs/bitcoin), [`k256`](https://docs.rs/k256), and [`ed25519-dalek`](https://docs.rs/ed25519-dalek) on top of a unified `Wallet` + `Derive` trait surface; every library crate builds under `no_std + alloc`, mnemonics and private keys wrap in `Zeroizing<T>` and wipe on drop, and every chain's pipeline is pinned against independent reference implementations (bitcoinjs-lib, @ton/core, @noble/hashes, NIP-06 official vectors, ethanmarcuss/spark-address, …).

> **See also** [`signer`](https://github.com/qntx/signer) — the companion transaction-signing toolkit that consumes kobe's derived accounts via `Signer::from_derived`.

<p align="center">
  <img src="demo.gif" alt="Kobe CLI Demo"/>
</p>

## Quick Start

### Install the CLI

**Shell** (macOS / Linux):

```bash
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
# Generate new wallets (default: 12-word English mnemonic, 1 account)
kobe btc    new                              # P2WPKH (Native SegWit), mainnet
kobe btc    new -a taproot -w 24 -c 5        # 5 Taproot addresses, 24-word mnemonic
kobe evm    new                              # Ethereum (MetaMask-compatible)
kobe evm    new --style ledger-live -c 3     # Ledger Live layout, 3 accounts
kobe svm    new                              # Solana (Phantom / Backpack / Solflare)
kobe cosmos new                              # Cosmos Hub (`cosmos1…`)
kobe aptos  new                              # Aptos
kobe sui    new                              # Sui
kobe ton    new                              # TON wallet v5r1 (UQ… non-bounceable)
kobe ton    new --bounceable                 # TON bounceable (EQ…), smart-contract style
kobe ton    new --testnet --workchain -1     # TON testnet masterchain
kobe ton    new --style ledger-live          # TON Ledger Live path
kobe tron   new                              # Tron (base58check `T…`)
kobe fil    new                              # Filecoin (`f1…` secp256k1)
kobe spark  new                              # Spark (Bitcoin L2), bech32m `spark1…`
kobe spark  new --network testnet            # Spark testnet (`sparkt1…`)
kobe xrpl   new                              # XRP Ledger classic `r…`
kobe nostr  new                              # Nostr NIP-06 (`nsec` / `npub`, NIP-19)

# Import from an existing mnemonic
kobe evm    import -m "abandon abandon ... about"

# JSON output — stable, script- and agent-friendly
kobe evm    new --json
```

Every chain subcommand accepts the shared flags `-w/--words`, `-c/--count`, `-p/--passphrase`, and `--qr` through a flattened `SimpleArgs` group, so ergonomics stay consistent across the 12 networks.

### Library Usage

```rust
use kobe::prelude::*;     // Wallet, Derive, DeriveExt, DerivationStyle trait, ...
use kobe::evm::Deriver;   // or kobe::btc, kobe::svm, kobe::cosmos, ...

// Import from mnemonic
let wallet = Wallet::from_mnemonic(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    None,  // optional passphrase
)?;

// Derive addresses (accessor methods — fields are private for zeroization safety)
let eth = kobe::evm::Deriver::new(&wallet).derive(0)?;
let btc = kobe::btc::Deriver::new(&wallet, kobe::btc::Network::Mainnet)?.derive(0)?;
let sol = kobe::svm::Deriver::new(&wallet).derive(0)?;

println!("ETH: {}", eth.address());  // 0x9858EfFD232B4033E47d90003D41EC34EcaEda94
println!("BTC: {}", btc.address());  // bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
println!("SOL: {}", sol.address());  // HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk

// Chain-specific extensions via newtypes: `BtcAccount` extends `DerivedAccount`
// with `private_key_wif()`, `address_type()`, `bip32_path()`; `SvmAccount`
// exposes `keypair_base58()`. Both `Deref` to the unified `DerivedAccount`.
println!("BTC WIF: {}", btc.private_key_wif().as_str());
```

String-path entry points are uniform across every chain. Bitcoin additionally
exposes an explicit-type escape hatch for non-standard paths:

```rust
use kobe::btc::{AddressType, Deriver, Network};

let deriver = Deriver::new(&wallet, Network::Mainnet)?;
let p2wpkh = deriver.derive_at("m/84'/0'/0'/0/0")?;                    // infer type from purpose
let taproot = deriver.derive_at("m/86'/0'/0'/0/0")?;                   // infer type from purpose
let custom  = deriver.derive_at_with("m/7'/0'/0'/0/0", AddressType::P2tr)?; // non-standard purpose
```

`DerivationStyle` is a shared trait implemented by every chain's style enum.
`kobe::prelude::*` brings it into scope so `style.path(i)` / `style.name()`
work directly:

```rust
use kobe::prelude::*;
use kobe::evm::DerivationStyle;

let style: DerivationStyle = "ledger-live".parse()?;           // FromStr
assert_eq!(style.path(0), "m/44'/60'/0'/0/0");                 // trait method
for variant in <DerivationStyle as kobe::DerivationStyle>::all() {
    println!("{variant}: {}", variant.path(0));
}
```

```rust
// Generate new wallet
let wallet = Wallet::generate(12, None)?;  // 12-word mnemonic
println!("Mnemonic: {}", wallet.mnemonic());
```

## Supported Chains

| Chain      | Crate          | Curve                 | BIP-44 coin | Default path                | Address format                           |
| ---------- | -------------- | --------------------- | ----------- | --------------------------- | ---------------------------------------- |
| Bitcoin    | `kobe-btc`     | secp256k1 (BIP-32)    | 0           | `m/84'/0'/0'/0/{i}`         | P2PKH / P2SH-P2WPKH / P2WPKH / P2TR      |
| Ethereum   | `kobe-evm`     | secp256k1 (BIP-32)    | 60          | `m/44'/60'/0'/0/{i}`        | EIP-55 `0x…`                             |
| Cosmos     | `kobe-cosmos`  | secp256k1 (BIP-32)    | 118 *       | `m/44'/118'/0'/0/{i}`       | Bech32 `cosmos1…` (HRP configurable)     |
| Tron       | `kobe-tron`    | secp256k1 (BIP-32)    | 195         | `m/44'/195'/0'/0/{i}`       | Base58Check `T…`                         |
| Filecoin   | `kobe-fil`     | secp256k1 (BIP-32)    | 461         | `m/44'/461'/0'/0/{i}`       | Base32 `f1…`                             |
| Spark      | `kobe-spark`   | secp256k1 (BIP-32)    | 8797555 †   | `m/8797555'/{i}'/0'`        | Bech32m `spark1…` / `sparkt1…` / …       |
| XRP Ledger | `kobe-xrpl`    | secp256k1 (BIP-32)    | 144         | `m/44'/144'/0'/0/{i}`       | Base58Check (XRPL alphabet) `r…`         |
| Nostr      | `kobe-nostr`   | secp256k1 (BIP-340)   | 1237        | `m/44'/1237'/{i}'/0/0`      | NIP-19 `npub1…` / `nsec1…`               |
| Solana     | `kobe-svm`     | Ed25519 (SLIP-10)     | 501         | `m/44'/501'/{i}'/0'`        | Base58 + optional 64-byte keypair        |
| Sui        | `kobe-sui`     | Ed25519 (SLIP-10)     | 784         | `m/44'/784'/{i}'/0'/0'`     | `0x` + hex(`BLAKE2b-256(0x00 ‖ pubkey)`) |
| TON        | `kobe-ton`     | Ed25519 (SLIP-10)     | 607         | `m/44'/607'/{i}'`           | wallet v5r1 (`UQ…` / `EQ…` / `0Q…` / …)  |
| Aptos      | `kobe-aptos`   | Ed25519 (SLIP-10)     | 637         | `m/44'/637'/{i}'/0'/0'`     | `0x` + hex(`SHA3-256(pubkey ‖ 0x00)`)    |

\* Cosmos coin type defaults to `118`; Terra (`330`), Secret (`529`), Kava (`459`), and custom chains are selectable via `ChainConfig`.
† Spark purpose `8797555` is Spark-specific (`SHA-256("spark")` truncated), not a BIP-44 assignment.

## Design

- **12 chains** — Aptos, Bitcoin, Ethereum, Solana, Cosmos, Tron, Sui, TON, Filecoin, Spark, XRP Ledger, Nostr — one BIP-39 seed
- **Zero hand-written cryptography** — `bip39` for mnemonic ↔ entropy, `bip32` / `bitcoin` for BIP-32 secp256k1, `k256` for secp256k1 encodings, `ed25519-dalek` for SLIP-10 Ed25519; hashing via `sha2` / `sha3` / `blake2` / `ripemd`; encoding via `bech32` / `bs58`
- **Unified derivation contract** — shared `Derive` trait with an associated `Account` type + shared `DerivationStyle` trait; every chain has typed public keys via `DerivedPublicKey`, one shared `DeriveError`, and one shared `ParseDerivationStyleError`
- **Consistent entry points** — `derive` / `derive_with` / `derive_at` / `derive_at_with` across every chain (Bitcoin's structured path also available as `derive_structured`)
- **HD standards** — BIP-32, BIP-39, BIP-44 / 49 / 84 / 86, SLIP-10, NIP-06, NIP-19
- **Derivation styles** — Standard, Ledger Live, Ledger Legacy, Trust, Phantom, Backpack, Tonkeeper — with `FromStr` aliases and an accepted-token diagnostic on `ParseDerivationStyleError`
- **Cross-implementation KATs** — every chain is pinned against independent references (bitcoinjs-lib, @ton/core, @noble/hashes, NIP-06 official vectors, ethanmarcuss/spark-address, BIP-84 / BIP-86 / EIP-55 / SLIP-10 test vectors) — no self-confirming dumps
- **`no_std` + `alloc`** — every library crate compiles on `thumbv7m-none-eabi` under CI; embedded / WASM ready
- **Security hardened** — mnemonics, seeds, private keys, WIFs, `nsec`s, and Solana keypairs wrapped in `Zeroizing<T>`; no key material is logged or persisted
- **Signer integration** — [`signer`](https://github.com/qntx/signer) consumes every `DerivedAccount` / `BtcAccount` / `SvmAccount` / `NostrAccount` via `Signer::from_derived` behind its `kobe` feature flag
- **Strict linting** — Clippy `pedantic` + `nursery` + `correctness` (deny), `rust_2018_idioms` deny, zero warnings on nightly

## Crates

See **[`crates/README.md`](crates/README.md)** for the full crate table, dependency graph, and feature flag reference.

## Security

This library has **not** been independently audited. Use at your own risk.

- Mnemonics, seeds, and derived private keys wrapped in [`zeroize`](https://docs.rs/zeroize) — wiped from memory on drop
- Chain-specific secret encodings (BTC WIF, Nostr `nsec`, Solana 64-byte keypair) are wrapped in `Zeroizing<String>` / `Zeroizing<[u8; N]>`
- Random generation uses the OS-provided CSPRNG via [`getrandom`](https://docs.rs/getrandom); `Wallet::generate_in_with` accepts a caller-supplied `CryptoRng` on embedded / WASM targets where OS entropy is unavailable
- `secp256k1` contexts are cached on `Deriver` to avoid the ~768 KB per-call setup cost
- Environment-variable mutation and `std::mem::{transmute, forget}` are denied at the lint level
- No key material is logged or persisted by the workspace

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
