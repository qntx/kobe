# Crates

| Crate | | Description |
| --- | --- | --- |
| **[`kobe`](kobe/)** | [![crates.io][kobe-crate]][kobe-crate-url] [![docs.rs][kobe-doc]][kobe-doc-url] | Umbrella crate — re-exports `kobe-primitives` + feature-gated chain crates |
| **[`kobe-primitives`](kobe-primitives/)** | [![crates.io][kobe-primitives-crate]][kobe-primitives-crate-url] [![docs.rs][kobe-primitives-doc]][kobe-primitives-doc-url] | Core library — BIP-39/32, SLIP-10, Wallet, `no_std` + `alloc` |
| **[`kobe-btc`](kobe-btc/)** | [![crates.io][kobe-btc-crate]][kobe-btc-crate-url] [![docs.rs][kobe-btc-doc]][kobe-btc-doc-url] | Bitcoin — P2PKH, P2SH-P2WPKH, P2WPKH, P2TR |
| **[`kobe-evm`](kobe-evm/)** | [![crates.io][kobe-evm-crate]][kobe-evm-crate-url] [![docs.rs][kobe-evm-doc]][kobe-evm-doc-url] | Ethereum — MetaMask / Ledger Live / Ledger Legacy styles |
| **[`kobe-svm`](kobe-svm/)** | [![crates.io][kobe-svm-crate]][kobe-svm-crate-url] [![docs.rs][kobe-svm-doc]][kobe-svm-doc-url] | Solana — Phantom / Trust / Ledger Live styles |
| **[`kobe-cosmos`](kobe-cosmos/)** | [![crates.io][kobe-cosmos-crate]][kobe-cosmos-crate-url] [![docs.rs][kobe-cosmos-doc]][kobe-cosmos-doc-url] | Cosmos — configurable HRP and coin type |
| **[`kobe-tron`](kobe-tron/)** | [![crates.io][kobe-tron-crate]][kobe-tron-crate-url] [![docs.rs][kobe-tron-doc]][kobe-tron-doc-url] | Tron — base58check addresses |
| **[`kobe-sui`](kobe-sui/)** | [![crates.io][kobe-sui-crate]][kobe-sui-crate-url] [![docs.rs][kobe-sui-doc]][kobe-sui-doc-url] | Sui — SLIP-10 Ed25519 + BLAKE2b-256 |
| **[`kobe-ton`](kobe-ton/)** | [![crates.io][kobe-ton-crate]][kobe-ton-crate-url] [![docs.rs][kobe-ton-doc]][kobe-ton-doc-url] | TON — wallet v5r1, Tonkeeper / Ledger Live styles |
| **[`kobe-fil`](kobe-fil/)** | [![crates.io][kobe-fil-crate]][kobe-fil-crate-url] [![docs.rs][kobe-fil-doc]][kobe-fil-doc-url] | Filecoin — f1 secp256k1 addresses |
| **[`kobe-spark`](kobe-spark/)** | [![crates.io][kobe-spark-crate]][kobe-spark-crate-url] [![docs.rs][kobe-spark-doc]][kobe-spark-doc-url] | Spark — Lightning-compatible addresses |
| **[`kobe-xrpl`](kobe-xrpl/)** | [![crates.io][kobe-xrpl-crate]][kobe-xrpl-crate-url] [![docs.rs][kobe-xrpl-doc]][kobe-xrpl-doc-url] | XRP Ledger — classic `r`-addresses, secp256k1 |
| **[`kobe-cli`](kobe-cli/)** | [![crates.io][kobe-cli-crate]][kobe-cli-crate-url] | CLI — generate, import, derive across all chains |

## Dependency Graph

```text
kobe-cli
  └── kobe (umbrella)
        ├── kobe-primitives
        ├── kobe-btc    ── kobe-primitives (bitcoin Xpriv)
        ├── kobe-evm    ── kobe-primitives/bip32
        ├── kobe-svm    ── kobe-primitives/slip10
        ├── kobe-cosmos ── kobe-primitives/bip32
        ├── kobe-tron   ── kobe-primitives/bip32
        ├── kobe-spark  ── kobe-primitives/bip32
        ├── kobe-fil    ── kobe-primitives/bip32
        ├── kobe-ton    ── kobe-primitives/slip10
        ├── kobe-sui    ── kobe-primitives/slip10
        └── kobe-xrpl   ── kobe-primitives/bip32
```

## Feature Flags

The umbrella `kobe` crate provides fine-grained feature control:

| Feature | Default | Description |
| --- | --- | --- |
| `std` | ✅ | Enable `std` support |
| `alloc` | ✅ | Enable `alloc` (implied by `std`) |
| `rand` | | Enable random mnemonic generation |
| `camouflage` | | Enable mnemonic camouflage encryption |
| `btc` | ✅ | Bitcoin chain support |
| `evm` | ✅ | Ethereum chain support (enables `bip32`) |
| `svm` | ✅ | Solana chain support (enables `slip10`) |
| `cosmos` | | Cosmos chain support (enables `bip32`) |
| `tron` | | Tron chain support (enables `bip32`) |
| `spark` | | Spark chain support (enables `bip32`) |
| `fil` | | Filecoin chain support (enables `bip32`) |
| `ton` | | TON chain support (enables `slip10`) |
| `sui` | | Sui chain support (enables `slip10`) |
| `xrpl` | | XRP Ledger chain support (enables `bip32`) |
| `all-chains` | | Enable all chain crates |

[kobe-crate]: https://img.shields.io/crates/v/kobe.svg
[kobe-crate-url]: https://crates.io/crates/kobe
[kobe-primitives-crate]: https://img.shields.io/crates/v/kobe-primitives.svg
[kobe-primitives-crate-url]: https://crates.io/crates/kobe-primitives
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
[kobe-primitives-doc]: https://img.shields.io/docsrs/kobe-primitives.svg
[kobe-primitives-doc-url]: https://docs.rs/kobe-primitives
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
[kobe-xrpl-crate]: https://img.shields.io/crates/v/kobe-xrpl.svg
[kobe-xrpl-crate-url]: https://crates.io/crates/kobe-xrpl
[kobe-xrpl-doc]: https://img.shields.io/docsrs/kobe-xrpl.svg
[kobe-xrpl-doc-url]: https://docs.rs/kobe-xrpl
