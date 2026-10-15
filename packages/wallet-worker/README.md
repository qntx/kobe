# @qntx/wallet-worker

Web and Node host for [`@qntx/wallet`](https://www.npmjs.com/package/@qntx/wallet): spawns the
wallet kernel in a Worker (`dist/kernel.worker.js` / `dist/kernel.node.js`, bundled), keeps the
encrypted vault in IndexedDB (Web) or a main-thread memory store (Node), and runs the WebAuthn
PRF passkey ceremony on the main thread. Peer dependency: the exact `@qntx/wallet` release this
kernel was built against — the host/kernel protocol requires it.

```bash
npm install @qntx/wallet-worker @qntx/wallet
```

## Web

`@qntx/wallet-worker/browser`:

```ts
import { createWebWallet } from "@qntx/wallet-worker/browser";

const wallet = await createWebWallet({
  passkey: {
    rpId: "app.example.com",
    rpName: "Example",
    walletSalt: "example/wallet",
    vaultSalt: "example/vault",
  },
  autoLock: { platform: "web", idleMinutes: 15 },
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

- Secrets exist only inside the kernel Worker; lock destroys the worker, the vault image
  (ciphertext + public headers) persists in the store.
- The Web host is a **hot wallet**. CSP needs `worker-src 'self'`; Vite needs
  `optimizeDeps.exclude: ["@qntx/wallet-worker"]`.
- `@qntx/wallet/host` is for host packages only — not application API.

## License

MIT OR Apache-2.0
