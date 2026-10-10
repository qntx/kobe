# Changelog

All notable changes to `@qntx/wallet` are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- The `@qntx/wallet` kernel (HD derivation, per-chain accounts and signers for EVM / SVM / BTC / Nostr, vault envelopes and passkey wallets) now lives in this repository under `packages/wallet`, published as `@qntx/wallet` and versioned independently of the Rust workspace (`wallet-v*` tags).
- `Wallet.id()` — stable 16-hex wallet identifier shared with `kobe-core`.
- EVM signing: EIP-191 personal messages, EIP-712 v4 typed data, EIP-7702 authorizations, and transaction envelopes for legacy EIP-155, EIP-2930, EIP-1559 and EIP-7702 with strict unsigned-envelope validation; address parsing with EIP-55 checksum validation and signature recovery are public pure functions.

### Changed

- Nostr signing moved to `@qntx/nostr`; `nostr` keeps account derivation and `nsec`/`npub` encoding only, and `nsec()` is computed on demand rather than stored.
- Solana derivation styles renamed to `bip44-change` (`m/44'/501'/i'/0'`), `bip44` (`m/44'/501'/i'` — now also covers Ledger Live) and `legacy`; the five-segment Ledger path was removed.

### Removed

- Chains outside the first batch (aptos, arweave, casper, cosmos, fil, spark, sui, ton, tron, xrpl), the `./secret` credential helpers, the package root barrel, and the duplicated per-signer factory exports — each signer is constructed exclusively through its `XxxSigner` namespace.
