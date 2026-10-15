# @qntx/wallet

Public API surface of the qntx wallet: the `Wallet` interface, the immutable `WalletSnapshot`,
`WalletError`, the core API groups (vault, wallets, dataKeys), the host/kernel wire protocol, and
the `@qntx/wallet/nostr` subpath — the first protocol module. This package contains no runtime of
its own — a `Wallet` comes from a host package that spawns the kernel, currently
[`@qntx/wallet-worker`](https://www.npmjs.com/package/@qntx/wallet-worker) for Web and Node.

```bash
npm install @qntx/wallet @qntx/wallet-worker
```

## Usage

```ts
import { createWebWallet } from "@qntx/wallet-worker/browser";

const wallet = await createWebWallet({
  passkey: {
    rpId: "app.example.com", // the origin's effective domain or a registrable parent
    rpName: "Example",
    walletSalt: "example/wallet",
    vaultSalt: "example/vault",
  },
  autoLock: { platform: "web", idleMinutes: 15 },
});

// First run: create the wallet and register its passkey.
const created = await wallet.wallets.createWithPasskey({ name: "Example Wallet" });

// Later runs: unlock with the passkey (or a password factor).
await wallet.vault.unlock({ kind: "passkey" });

// The Nostr module lives in its own subpath — the root entry never pulls @qntx/nostr.
import { nostr } from "@qntx/wallet/nostr";

const key = await nostr(wallet).deriveKey(created.walletId, 0);
// A proxy NostrSigner — resolves the kernel key per call and survives lock/unlock.
const signer = nostr(wallet).signer(key.ref);
const event = await signer.signEvent({
  kind: 1,
  created_at: Math.floor(Date.now() / 1000),
  tags: [],
  content: "gm",
});
```

### React

`getSnapshot` and `subscribe` are bound properties, safe to pass unbound:

```tsx
import { useSyncExternalStore } from "react";

const snapshot = useSyncExternalStore(wallet.subscribe, wallet.getSnapshot);
// snapshot.vault: "uninitialized" | "locked" | "unlocked" | "corrupted" | "unsupported" | "unavailable"
// snapshot.lockReason: "cold-start" | "user" | "idle" | "background" | "expired" | "crashed" | "invalidated"
```

What to do with each vault state:

- `corrupted` — stored ciphertext or a public header failed authentication. Confirm it is real
  (a reload that keeps reporting `corrupted`), then `wallet.vault.reset()` is the only way
  forward and destroys the vault. Never reset on a single sighting.
- `unsupported` — the vault was written by a newer build. Update the app; do not reset.
- `unavailable` — the vault store failed transiently. Retry; the kernel retries a load on the
  next request itself.

## Security notes

- Secrets (seed, keys, DEK, PRF output) exist only inside the kernel's Web Worker; the host
  thread sees ciphertext and public headers only.
- The Web host is a **hot wallet**: it protects against the host page reading secrets, not
  against a compromised browser or device.
- Your CSP must allow the bundled worker: `worker-src 'self'` (the worker loads from your own
  origin — a stricter policy breaks the wallet).
- Vite users: set `optimizeDeps.exclude: ["@qntx/wallet-worker"]` so the worker URL survives dev.
- `@qntx/wallet/host` is reserved for host packages — applications must not use it.
- `wallet.vault.lock()` resolves immediately and terminates the worker — it never waits on the
  kernel queue, and every kernel call has a timeout that surfaces `crashed`.
- Password unlock is rate-limited inside the kernel: five counted misses arm a backoff
  (30 s → 60 s → 300 s), a `rate-limited` error carries `retryAt`, and retrying during backoff
  does not push the deadline. Passkey unlocks are never gated by it.
- Sessions idle-lock after 5, 15 or 60 minutes (`autoLock.idleMinutes`, worker-enforced) with a
  fixed 12-hour maximum, measured on a monotonic clock — a wall-clock jump can neither extend
  nor shorten a session.
- Changing the password or removing a factor rotates the vault DEK: sessions in other tabs lock
  with reason `invalidated` and must re-unlock. Adding a passkey factor keeps the current DEK.
- `passkey.rpId`, `walletSalt` and `vaultSalt` are permanent identifiers — changing any of them
  makes every existing passkey factor and passkey-derived wallet unrecoverable, and the salts
  must differ. Moving domains requires WebAuthn related origins (`/.well-known/webauthn`); offer
  `exportMnemonic` for passkey-derived wallets so they survive an RP migration. `connectKernel`
  rejects an empty or colliding config before the worker spawns.
- Standalone Nostr keys carry `backedUp`: imports start `true`, generated keys `false`, and a
  successful `nostr.exportKey` marks the record — surface the flag so users actually back up.
  `ncryptsec` always carries NIP-49 key-security byte `0x02` and its scrypt `logN` is capped
  (18 on Web, 20 on Node); oversized values fail `unsupported` before scrypt runs.
- Requests are capped at 1 MiB on both sides of the channel; larger calls fail `invalid-input`
  without reaching the kernel.
- `dist/kernel.manifest.json` in `@qntx/wallet-worker` records the protocol version, vault
  format, pinned dependency versions/integrities and the SHA-256 of each kernel bundle.

## License

MIT OR Apache-2.0
