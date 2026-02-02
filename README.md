# kobe

[![Crates.io][crates-badge]][crates-url]
[![Documentation][docs-badge]][docs-url]
[![License][license-badge]](#license)

[crates-badge]: https://img.shields.io/crates/v/kobe.svg
[crates-url]: https://crates.io/crates/kobe
[docs-badge]: https://img.shields.io/docsrs/kobe
[docs-url]: https://docs.rs/kobe
[license-badge]: https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg

Deterministic cryptocurrency wallet derivation for Bitcoin, Ethereum, and Solana.

## Overview

**kobe** is a minimal, `no_std`-compatible Rust library for HD wallet derivation across multiple blockchain networks. It provides a unified interface for BIP39 mnemonic management and chain-specific address generation.

### Crates

| Crate | Description |
| ----- | ----------- |
| [`kobe`][kobe] | Core BIP39 wallet and seed derivation |
| [`kobe-btc`][kobe-btc] | Bitcoin derivation (BIP32/44/49/84/86) |
| [`kobe-eth`][kobe-eth] | Ethereum derivation (BIP44, Ledger paths) |
| [`kobe-sol`][kobe-sol] | Solana derivation (SLIP-10 Ed25519) |
| [`kobe-cli`][kobe-cli] | Command-line interface |

[kobe]: https://crates.io/crates/kobe
[kobe-btc]: https://crates.io/crates/kobe-btc
[kobe-eth]: https://crates.io/crates/kobe-eth
[kobe-sol]: https://crates.io/crates/kobe-sol
[kobe-cli]: https://crates.io/crates/kobe-cli

## Features

- **Multi-chain support** — Bitcoin (P2PKH, P2SH, P2WPKH, P2TR), Ethereum, Solana
- **HD derivation** — BIP32, BIP39, BIP44, SLIP-10
- **Multiple derivation styles** — Standard, Ledger Live, Ledger Legacy, Trust Wallet
- **`no_std` compatible** — Suitable for embedded and WASM targets
- **Zeroizing** — Sensitive key material is zeroized on drop

## Installation

### Library

```toml
[dependencies]
kobe = "0.4"
kobe-btc = "0.4"
kobe-eth = "0.4"
kobe-sol = "0.4"
```

### CLI

```bash
cargo install kobe-cli
```

## Usage

### As a Library

```rust
use kobe::Wallet;
use kobe_btc::{Deriver as BtcDeriver, Network, AddressType};
use kobe_eth::Deriver as EthDeriver;
use kobe_sol::Deriver as SolDeriver;

// Generate a new 12-word mnemonic wallet
let wallet = Wallet::generate(12, None)?;

// Or import from existing mnemonic
let wallet = Wallet::from_mnemonic(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    None,
)?;

// Derive Bitcoin addresses (P2WPKH by default)
let btc = BtcDeriver::new(&wallet, Network::Mainnet)?;
let addr = btc.derive(0)?;
println!("{}", addr.address);  // bc1q...

// Derive Ethereum addresses
let eth = EthDeriver::new(&wallet);
let addr = eth.derive(0)?;
println!("{}", addr.address);  // 0x...

// Derive Solana addresses
let sol = SolDeriver::new(&wallet);
let addr = sol.derive(0)?;
println!("{}", addr.address);  // Base58...
```

### As a CLI

```bash
# Generate new wallets
kobe btc new
kobe eth new
kobe sol new

# Generate multiple addresses
kobe btc new -c 5
kobe eth new -c 10 --style ledger-live

# Import from mnemonic
kobe btc import "your twelve word mnemonic phrase here"

# Generate random single-key wallet (no mnemonic)
kobe eth random
```

## Security

This library has **not** been independently audited. Use at your own risk.

Key material handling:

- Private keys use `zeroize` for secure memory cleanup
- No key material is logged or persisted by the library
- Random generation uses OS-provided CSPRNG via `rand_core::OsRng`

## License

This project is licensed under either of the following licenses, at your option:

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or [https://www.apache.org/licenses/LICENSE-2.0](https://www.apache.org/licenses/LICENSE-2.0))
- MIT license ([LICENSE-MIT](LICENSE-MIT) or [https://opensource.org/licenses/MIT](https://opensource.org/licenses/MIT))

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache-2.0 license, shall be dually licensed as above, without any additional terms or conditions.
