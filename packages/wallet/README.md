# @qntx/wallet

Public API surface of the qntx wallet: the `Wallet` interface, the immutable `WalletSnapshot`,
`WalletError`, the API group types (vault, wallets, nostr, exports, dataKeys), and the host/kernel
wire protocol. This package contains no runtime of its own — a `Wallet` comes from a host package
that spawns the kernel, currently [`@qntx/wallet-wasm`](https://www.npmjs.com/package/@qntx/wallet-wasm)
for Web and Node.

```bash
npm install @qntx/wallet @qntx/wallet-wasm
```

## Usage

```ts
import { createWebWallet } from "@qntx/wallet-wasm/browser";

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

// A proxy NostrSigner — resolves the kernel key per call and survives lock/unlock.
const signer = wallet.nostr.signer(created.nostr.ref);
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
// snapshot.vault: "uninitialized" | "locked" | "unlocked" | "corrupted"
```

## Security notes

- Secrets (seed, keys, DEK, PRF output) exist only inside the kernel's Web Worker; the host
  thread sees ciphertext and public headers only.
- The Web host is a **hot wallet**: it protects against the host page reading secrets, not
  against a compromised browser or device.
- Your CSP must allow the bundled worker: `worker-src 'self'` (the worker loads from your own
  origin — a stricter policy breaks the wallet).
- Vite users: set `optimizeDeps.exclude: ["@qntx/wallet-wasm"]` so the worker URL survives dev.
- `@qntx/wallet/host` is reserved for host packages — applications must not use it.
- A vault that reports `corrupted` cannot be unlocked; `wallet.vault.reset()` is the only way
  forward and destroys the stored vault.

## License

MIT OR Apache-2.0
