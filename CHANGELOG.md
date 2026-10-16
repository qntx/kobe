# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A `vX.Y.Z` tag runs `publish-npm.yml` (publishing `packages/wallet` and `packages/wallet-worker` via npm trusted publishing / OIDC). `@qntx/wallet-kernel` is private and only bundled into the host packages.

## [Unreleased]

The E0 hardening series (#91–#108): the vault is fail-closed, cryptographically authenticated,
race-safe across tabs, and resistant to storage tampering, factor misuse, session expiry,
request abuse and cross-host stale state.

### Added

- `WalletSnapshot.vault` reports `unsupported` (written by a newer build — update the app) and `unavailable` (transient store failure — retry) alongside `corrupted`; `lockReason` reports `invalidated` when another tab's factor change rotated the vault DEK. New `WalletError` codes: `wrong-passkey`, `conflict`, `unsupported`, `unavailable` (#92, #93).
- `NostrKeyInfo.backedUp` on standalone keys (nsec/ncryptsec/generated): imported keys report `true`, generated keys `false`, and a successful `nostr.exportKey` re-seals the record with `backedUp: true` (#102).
- `@qntx/wallet/host`: `PASSKEY_PURPOSE_WALLET`/`PASSKEY_PURPOSE_VAULT` and `PrfResult.userHandle`; the WebAuthn ceremony returns the assertion's `userHandle` (#95, #101).
- `@qntx/wallet-worker`: `dist/kernel.manifest.json` records the protocol version, vault format, each pinned kernel dependency's bun.lock integrity and the SHA-256 of each worker bundle (#107).
- `vectors/records.json` and `vectors/protocol.json` fix the public-header/vault-meta layouts and the wire-protocol shapes (#107).
- CI runs `check:pkg` (publint + attw) and v8 coverage on pull requests; browser tests run on WebKit and Firefox for the specs that do not need the CDP virtual authenticator (#108).
- `ConnectOptions.presence`: the host injects a user-activity source; the wallet throttles it to one `session.touch` per 30 s and only while a session exists. On the Web the source listens for pointer, key, wheel and touch input plus `visibilitychange` back to `visible`.
- Browser tests now run against the production `vite build` + `vite preview` output as a `chromium-build` project alongside the dev server.
- `createSoftwarePasskey(seed, { synced })` — `synced` defaults to `true`; pass `false` to exercise a device-bound credential.

### Changed

- **BREAKING:** the vault store is format 2 — atomic revision-guarded commits, authenticated public headers and factor wrap v2 (each factor header carries an X25519 `publicKey`). Vaults written by older builds report `unsupported` (#92, #93, #100).
- **BREAKING:** `wallet.vault.lock()` resolves immediately on the host and terminates the worker — it no longer waits on the kernel queue; kernel calls time out instead of hanging (#97).
- **BREAKING:** `restoreWithPasskey` rejects assertions whose `userHandle` is missing or not wallet-purpose (`wrong-passkey`); `connectKernel` validates `PasskeyConfig` — non-empty `rpId`/`rpName`, distinct salts — synchronously before spawning (#95, #101).
- Changing the password or removing a factor rotates the vault DEK and invalidates sessions in other tabs (they lock with reason `invalidated`); adding a passkey factor keeps the current DEK (#96, #100).
- ncryptsec exports always carry NIP-49 key-security byte `0x02`; imports prevalidate the bech32 payload before scrypt runs, cap `logN` by policy (18 on Web, 20 on Node) and map failures precisely — `invalid-input`, `unsupported`, `unavailable` or `wrong-password` (#106).
- Requests are capped at 1 MiB, measured on the whole message envelope and enforced on both sides of the channel (#104).
- Every `@qntx/wallet-kernel` runtime dependency is an exact pin; `scripts/check-version.ts` fails unless each pin equals what `bun.lock` resolves (#107).
- **BREAKING:** `WalletInfo.backedUp` is replaced by `WalletInfo.backup` — `"mnemonic"`, `"passkey"` or `"none"`. Passkey wallets report the credential's real sync state (WebAuthn BE/BS flags on the Web); `exportMnemonic` upgrades the record to `"mnemonic"`. Standalone Nostr keys keep `backedUp`.
- **BREAKING:** `PrfResult` gains `synced`, and `wallet.createWithPasskey`/`wallet.restoreWithPasskey` carry it into the kernel.
- **BREAKING:** the kernel's idle model is presence-based on the Web (`KernelPolicy.activity`): signing and background requests no longer refresh the idle timer — user presence, `session.touch` and factor/user-facing operations do; the 12 h maximum is unchanged. Node keeps request-based activity. Failed requests never count as activity.
- **BREAKING:** the channel watchdog times only the queue head — a request queued behind a slow head is no longer timed while it waits; the head gets 60 s before the port is replaced. `MAX_BATCH` drops from 256 to 64 and `nostr.unwrapGiftWraps` accepts any number of events, chunking internally.
- **BREAKING:** the hidden-page 5-minute lock is removed; `pagehide` still locks and the idle timer is presence-driven.

### Fixed

- Password unlock is rate-limited inside the kernel: five counted failures arm a 30 s/60 s/300 s backoff, a `rate-limited` error carries `retryAt`, retries during backoff do not push the deadline, and passkey unlocks are never gated by password backoff (#91, #99).
- Vault-health classification no longer conflates corruption with transient I/O failure or newer-build data; a corrupted vault invalidates the live session immediately (#93, #94).
- Concurrent commits from two tabs resolve to exactly one writer — `expect-revision` guards make the loser a `conflict`, so a factor can never be lost (#92).
- Session deadlines (idle 5/15/60 minutes, fixed 12 h maximum) are owned by the worker and measured on a monotonic clock — a wall-clock jump cannot extend or shorten a session (#98).
- Live state is a function of the authenticated store image: key imports, deletes and wallet removals reconcile across tabs without re-unlock; a tampered record or planted factor row corrupts the vault (#96).
- IndexedDB `versionchange` closes the worker's connection so a newer-version open is never `blocked`; once the database is newer than the schema the vault reports `unsupported` (#105).
- The Node store's precondition failures surface `conflict` and RPC failures `unavailable` — never a hang.
- Shape validators and header parsers check own properties only — inherited names cannot satisfy or forge a field, and a missing required key is still reported missing (#103).
- A wrong passkey now consistently reports `wrong-passkey` — unlock, factor verification, and credential mismatches — instead of `integrity`.
- A stored Nostr key record whose authenticated plaintext does not match its record id latches the vault `corrupted`.
- `dataKeys.get` documentation corrected: the data key is random per vault — created on first use, stable across lock/unlock and DEK rotation, lost on reset or restore to another device; callers must be able to rebuild from it.

## [0.2.0] - 2026-10-15

### Removed

- **BREAKING:** `WalletOptions.logger` and the `WalletLogger` type — the option was declared but never wired to anything.

## [0.1.0] - 2026-10-15

### Added

- `@qntx/wallet`: the host-facing `Wallet` — an immutable snapshot for `useSyncExternalStore` (`uninitialized`, `locked`, `unlocked`, `corrupted`), core vault/wallet/data-key APIs, and one `WalletError` with typed codes. `@qntx/wallet/nostr` is the Nostr protocol module: `nostr(wallet)` returns key derivation/import/generation, guarded export and removal, and proxy Nostr signers whose results are verified on the main thread — the root entry never pulls `@qntx/nostr`. `@qntx/wallet/protocol` defines the strictly validated enclave protocol; `@qntx/wallet/host` is for host packages only.
- `@qntx/wallet-worker/browser`: `createWebWallet` runs the kernel in a module Worker with an IndexedDB vault, Web Locks and cross-tab change notifications, and performs the WebAuthn PRF ceremony on the main thread. Locking terminates the Worker.
- `@qntx/wallet-worker/node`: `createNodeWallet` runs the same kernel in `worker_threads`, with the test-only `createSoftwarePasskey`.
- The kernel: BIP-39 (random with a backup quiz, import, export), passkey wallets (PRF output as BIP-39 entropy), BIP-32 and NIP-06 derivation, `walletId`, an XChaCha20-Poly1305 vault whose public headers are authenticated and record-kind agnostic (an unknown kind reports `corrupted` rather than silently dropping data), password and passkey factors with online rate limiting, sessions with idle and absolute limits, a statically composed Nostr module (derived keys, nsec, ncryptsec, generated, NIP-46 client; NIP-04, NIP-44 and batched NIP-59 unwrapping).

[Unreleased]: https://github.com/qntx/wallet/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/qntx/wallet/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/qntx/wallet/releases/tag/v0.1.0
