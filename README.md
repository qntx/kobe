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

**`no_std`-compatible Rust toolkit for multi-chain HD wallet derivation — one BIP-39 seed, twelve networks, zero hand-written cryptography.**

Kobe derives standards-compliant accounts and addresses for Aptos, Bitcoin, Ethereum, Solana, Cosmos, Tron, Sui, TON, Filecoin, Spark, XRP Ledger, and Nostr (NIP-06 / NIP-19) from a single BIP-39 mnemonic. Every library crate builds under `no_std + alloc`; mnemonics, seeds, and private keys are wrapped in `Zeroizing<T>` and wiped on drop.

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

## Design

- **12 chains** — Aptos, Bitcoin, Ethereum, Solana, Cosmos, Tron, Sui, TON, Filecoin, Spark, XRP Ledger, Nostr — one BIP-39 seed
- **HD standards** — BIP-32, BIP-39, BIP-44/49/84/86, SLIP-10, NIP-06, NIP-19
- **Unified derivation contract** — shared `Derive` trait with an associated `Account` type + `DerivationStyle` trait; every chain has typed public keys via `DerivedPublicKey`, one shared `DeriveError`, and one shared `ParseDerivationStyleError`
- **Consistent entry points** — `derive` / `derive_with` / `derive_at` / `derive_at_with` across every chain (Bitcoin's structured path also available as `derive_structured`)
- **Derivation styles** — Standard, Ledger Live, Ledger Legacy, Trust, Phantom, Backpack, Tonkeeper — with `FromStr` aliases and an accepted-token diagnostic on `ParseDerivationStyleError`
- **`no_std` + `alloc`** — All library crates compile without `std`; embedded / WASM ready
- **Zeroizing** — Mnemonics, seeds, private keys, WIFs, `nsec`s, and Solana keypairs wrapped in `Zeroizing<T>`
- **Shared infrastructure** — SLIP-10 Ed25519 and BIP-32 secp256k1 derivation in `kobe-primitives`
- **KAT-verified** — Every chain has Known Answer Tests cross-verified with independent reference implementations (bitcoinjs-lib, @ton/core, @noble/hashes, NIP-06 official vectors, ethanmarcuss/spark-address, …)
- **Strict linting** — Clippy `pedantic` + `nursery` + `correctness` (deny), zero warnings

## Crates

See **[`crates/README.md`](crates/README.md)** for the full crate table, dependency graph, and feature flag reference.

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
