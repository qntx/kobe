<!-- markdownlint-disable MD033 MD041 -->

# wallet

Self-custodial wallet SDK for TypeScript: an isolated secret enclave (Web Worker, React Native kernel runtime) with HD derivation, a unified vault, and Nostr, Spark and multi-chain signing.

## Packages

- [`@qntx/wallet`](packages/wallet) — the host-facing API: `Wallet`, the immutable snapshot, `WalletError`, the wire protocol and the `@qntx/wallet/nostr` subpath.
- [`@qntx/wallet-worker`](packages/wallet-worker) — Web and Node hosts that spawn the kernel, persist the vault and run the passkey ceremony. `dist/kernel.manifest.json` records the protocol version, vault format, pinned library versions and bundle SHA-256.
- `@qntx/wallet-kernel` — the private enclave, bundled by the host packages, never published.

## Security model

Secrets (entropy, keys, DEK, PRF output) exist only inside the enclave; the host sees ciphertext and authenticated public headers. The vault is fail-closed: tampered data reports `corrupted`, newer-build data `unsupported`, transient store failures `unavailable` — and only confirmed corruption may be recovered with a destructive `vault.reset()`. Atomic revision-guarded commits make concurrent writers from two tabs resolve to one `conflict`; factor changes rotate the DEK and invalidate other sessions; password unlock is rate-limited inside the kernel; sessions idle-lock at 5/15/60 minutes with a fixed 12-hour maximum on a monotonic clock. Passkey `rpId` and PRF salts are permanent identifiers (see the package READMEs). Requests are capped at 1 MiB.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project shall be dual-licensed as above, without any additional terms or conditions.

---

<div align="center">

A **[QuantX](https://qntx.org)** open-source project.

<a href="https://qntx.org"><img alt="QuantX" width="369" src="https://raw.githubusercontent.com/qntx/.github/main/profile/qntx.svg" /></a>

Code is law. We write both.

</div>
