# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A `vX.Y.Z` tag runs `publish-npm.yml` (publishing `packages/wallet` and `packages/wallet-worker` via npm trusted publishing / OIDC). `@qntx/wallet-kernel` is private and only bundled into the host packages.

## [Unreleased]

## [0.1.0] - 2026-10-15

### Added

- `@qntx/wallet`: the host-facing `Wallet` — an immutable snapshot for `useSyncExternalStore` (`uninitialized`, `locked`, `unlocked`, `corrupted`), core vault/wallet/data-key APIs, and one `WalletError` with typed codes. `@qntx/wallet/nostr` is the Nostr protocol module: `nostr(wallet)` returns key derivation/import/generation, guarded export and removal, and proxy Nostr signers whose results are verified on the main thread — the root entry never pulls `@qntx/nostr`. `@qntx/wallet/protocol` defines the strictly validated enclave protocol; `@qntx/wallet/host` is for host packages only.
- `@qntx/wallet-worker/browser`: `createWebWallet` runs the kernel in a module Worker with an IndexedDB vault, Web Locks and cross-tab change notifications, and performs the WebAuthn PRF ceremony on the main thread. Locking terminates the Worker.
- `@qntx/wallet-worker/node`: `createNodeWallet` runs the same kernel in `worker_threads`, with the test-only `createSoftwarePasskey`.
- The kernel: BIP-39 (random with a backup quiz, import, export), passkey wallets (PRF output as BIP-39 entropy), BIP-32 and NIP-06 derivation, `walletId`, an XChaCha20-Poly1305 vault whose public headers are authenticated and record-kind agnostic (an unknown kind reports `corrupted` rather than silently dropping data), password and passkey factors with online rate limiting, sessions with idle and absolute limits, a statically composed Nostr module (derived keys, nsec, ncryptsec, generated, NIP-46 client; NIP-04, NIP-44 and batched NIP-59 unwrapping).

[Unreleased]: https://github.com/qntx/wallet/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/qntx/wallet/releases/tag/v0.1.0
