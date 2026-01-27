# Kobe

[![Crates.io](https://img.shields.io/crates/v/kobe.svg)](https://crates.io/crates/kobe)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)

Kobe is a lightweight cryptocurrency wallet toolkit written in Rust. It provides both a CLI tool and reusable libraries for Bitcoin and Ethereum wallet generation with full `no_std` support for embedded environments.

## Features

- **Multi-Chain Support** — Bitcoin (Legacy, SegWit, Native SegWit) and Ethereum
- **BIP39/BIP32/BIP44** — Standard mnemonic and HD wallet derivation
- **no_std Compatible** — Use in embedded systems and WebAssembly
- **Secure by Default** — Memory zeroization, no unsafe code
- **Minimal Dependencies** — Small binary size, fast compilation

## Installation

### CLI Tool

```bash
cargo install kobe
```

## Quick Start

### CLI Usage

Generate a Bitcoin wallet:

```bash
kobe btc new
```

```text
      Network      mainnet
      Address Type P2WPKH (Native SegWit)
      Mnemonic     sunny elephant wink holiday renew retire oak lady trial car develop giggle

      Path         m/84'/0'/0'/0/0
      Address      bc1qkwxmjfssd8vft2q8hpsvkqlehs8sawqjec3zlg
      Private Key  KwLNMJLXHawRxuPT7iEvcqoXc8rAc4QsXLpuMx98ekkpXwnZ2tNY
```

Generate an Ethereum wallet:

```bash
kobe eth new
```

```text
      Mnemonic     clean uniform crush friend dog episode message essay monitor phone left miracle

      Path         m/44'/60'/0'/0/0
      Address      0xD09FF64A19C37cc39d86EcCB9915ef0df0628146
      Private Key  0xb70cd395aba0e5a6ee3aee6956413b23b45e4505da590ec00839db7ade993d49
```

More options:

```bash
kobe btc new --words 24 --count 5 --testnet
kobe eth new --passphrase "secret" --count 3
kobe btc import --mnemonic "your twelve word mnemonic phrase here"
kobe eth import-key --key 0x...
```

### Library Usage

```rust
use kobe_core::Wallet;
use kobe_eth::Deriver;

// Generate a new wallet
let wallet = Wallet::generate(12, None)?;
println!("Mnemonic: {}", wallet.mnemonic());

// Derive Ethereum addresses
let deriver = Deriver::new(&wallet);
let account = deriver.derive(0, false, 0)?;

println!("Address: {}", account.address);
println!("Private Key: 0x{}", account.private_key_hex);
```

## License

This project is licensed under either of the following licenses, at your option:

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or [https://www.apache.org/licenses/LICENSE-2.0](https://www.apache.org/licenses/LICENSE-2.0))
- MIT license ([LICENSE-MIT](LICENSE-MIT) or [https://opensource.org/licenses/MIT](https://opensource.org/licenses/MIT))

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache-2.0 license, shall be dually licensed as above, without any additional terms or conditions.
