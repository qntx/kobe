# kobe

[![Crates.io][crates-badge]][crates-url]
[![Documentation][docs-badge]][docs-url]
[![License][license-badge]](#license)

[crates-badge]: https://img.shields.io/crates/v/kobe.svg
[crates-url]: https://crates.io/crates/kobe
[docs-badge]: https://img.shields.io/docsrs/kobe
[docs-url]: https://docs.rs/kobe
[license-badge]: https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg

**kobe** is a minimal, `no_std`-compatible Rust library for HD wallet derivation across multiple blockchain networks. It provides a unified interface for BIP39 mnemonic management and chain-specific address generation.

## Features

- **Multi-chain support** — Bitcoin (P2PKH, P2SH, P2WPKH, P2TR), Ethereum, Solana
- **HD derivation** — BIP32, BIP39, BIP44, SLIP-10
- **Multiple derivation styles** — Standard, Ledger Live, Ledger Legacy, Trust Wallet
- **`no_std` compatible** — Suitable for embedded and WASM targets
- **Zeroizing** — Sensitive key material is zeroized on drop

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
