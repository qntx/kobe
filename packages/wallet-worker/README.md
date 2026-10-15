# @qntx/wallet-worker

Web and Node host for [`@qntx/wallet`](https://www.npmjs.com/package/@qntx/wallet): spawns the
wallet kernel in a Worker (`dist/kernel.worker.js` / `dist/kernel.node.js`, bundled), keeps the
encrypted vault in IndexedDB (Web) or a main-thread store server (Node), and runs the WebAuthn
PRF passkey ceremony on the main thread. Peer dependency: the exact `@qntx/wallet` release this
kernel was built against — the host/kernel protocol requires it. `dist/kernel.manifest.json`
records the protocol version, vault format, every pinned kernel dependency's lockfile integrity
and the SHA-256 of each bundle.

```bash
npm install @qntx/wallet-worker @qntx/wallet
```

## Web

`@qntx/wallet-worker/browser`:

```ts
import { createWebWallet } from "@qntx/wallet-worker/browser";

const wallet = await createWebWallet({
  passkey: {
    rpId: "app.example.com", // permanent — see Security notes
    rpName: "Example",
    walletSalt: "example/wallet",
    vaultSalt: "example/vault",
  },
  autoLock: { platform: "web", idleMinutes: 15 }, // 5 | 15 | 60; max session 12 h
});

const created = await wallet.wallets.createWithPasskey({ name: "Example Wallet" });
await wallet.vault.unlock({ kind: "passkey" });

import { nostr } from "@qntx/wallet/nostr";

const key = await nostr(wallet).deriveKey(created.walletId, 0);
const signer = nostr(wallet).signer(key.ref);
```

## Node (tests and demos)

`@qntx/wallet-worker/node` runs the same kernel in a `node:worker_threads` Worker with an
in-memory vault store. `createSoftwarePasskey(seed)` is a **test-only** WebAuthn stand-in —
deterministic, no authenticator, anyone holding the seed owns the wallet:

```ts
import { createNodeWallet, createSoftwarePasskey } from "@qntx/wallet-worker/node";

const wallet = await createNodeWallet({
  passkey: { rpId: "qntx.test", rpName: "test", walletSalt: "t/wallet", vaultSalt: "t/vault" },
  autoLock: { platform: "web", idleMinutes: 15 },
  authenticator: createSoftwarePasskey(seed),
});
```

## Security notes

- Secrets exist only inside the kernel Worker; `vault.lock()` resolves immediately on the host
  and destroys the worker — the vault image (ciphertext + public headers) persists in the store.
- Session limits belong to the worker, not the page: `idleMinutes` accepts 5, 15 or 60 and the
  absolute session cap is a fixed 12 hours, measured on a monotonic clock.
- `passkey.rpId` and the two salts are permanent identifiers: changing them makes existing
  passkey factors and passkey-derived wallets unrecoverable. Moving domains needs WebAuthn
  related origins (`/.well-known/webauthn`); offer `exportMnemonic` for passkey-derived wallets.
- IndexedDB upgrades are never `blocked`: the worker closes its connection on `versionchange`,
  and once the database is newer than this build's schema the vault reports `unsupported` —
  update the app, do not reset.
- The Node store's RPC failures surface as `unavailable` and precondition failures as
  `conflict` — neither hangs a kernel call.
- The Web host is a **hot wallet**. CSP needs `worker-src 'self'`; Vite needs
  `optimizeDeps.exclude: ["@qntx/wallet-worker"]`.
- `@qntx/wallet/host` is for host packages only — not application API.

## License

MIT OR Apache-2.0
