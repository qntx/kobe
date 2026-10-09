# kobe-core

Multi-chain HD wallet derivation library

`Wallet::id()` returns a stable, non-secret wallet identifier — the first 16
hex chars of `SHA-256("kobe/wallet-id/v1" ‖ compressed BIP-32 master public
key)` — identical across the Rust and TS implementations
(`vectors/core/wallet-id.json`).

Part of [kobe](https://github.com/qntx/kobe).
