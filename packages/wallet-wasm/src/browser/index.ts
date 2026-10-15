/**
 * The Web host: `createWebWallet` spawns the bundled kernel worker (dist/kernel.worker.js) whose
 * vault lives in the worker's own IndexedDB. Lock destroys the worker; the vault survives in
 * IndexedDB, so the respawned worker reloads it. Page lifecycle locks: 5 minutes hidden or
 * `pagehide`. The WebAuthn ceremony runs on the main thread.
 */
import { WalletError } from "@qntx/wallet";
import type { Wallet, WalletOptions } from "@qntx/wallet";
import { connectKernel } from "@qntx/wallet/host";
import type { MainPort } from "@qntx/wallet/host";
import type { ProtocolValue } from "@qntx/wallet/protocol";

import type { BrowserWorkerInit } from "../shared.ts";
import { createWebAuthnPasskey } from "./passkey.ts";

const MAX_SESSION_MS = 12 * 3_600_000; // fixed: 12 h
const HIDDEN_LOCK_MS = 5 * 60_000; // lock after the page has been hidden for 5 minutes

async function bestEffort(task: () => Promise<unknown>): Promise<void> {
  try {
    await task();
  } catch {
    // Lifecycle hooks and persistence hints must never surface failures.
  }
}

export async function createWebWallet(options: WalletOptions): Promise<Wallet> {
  const { autoLock } = options;
  if (autoLock.platform !== "web") {
    throw new WalletError("invalid-input", "createWebWallet accepts only the web autoLock policy");
  }
  const init: BrowserWorkerInit = {
    t: "init",
    idleMs: autoLock.idleMinutes * 60_000,
    maxSessionMs: MAX_SESSION_MS,
  };
  const kernelUrl = new URL("kernel.worker.js", import.meta.url);
  const ceremony = createWebAuthnPasskey({
    id: options.passkey.rpId,
    name: options.passkey.rpName,
  });

  const spawn = (): MainPort => {
    const worker = new Worker(kernelUrl, { type: "module", name: "qntx-wallet" });
    // oxlint-disable-next-line unicorn/require-post-message-target-origin -- Worker.postMessage takes a transfer list, not an origin
    worker.postMessage(init); // the kernel validates it strictly before startKernel
    return {
      post: (message: ProtocolValue, transfer: ArrayBuffer[]) => {
        worker.postMessage(message, transfer);
      },
      listen: (handler) => {
        const listener = (event: MessageEvent): void => {
          handler(event.data);
        };
        worker.addEventListener("message", listener);
        return () => {
          worker.removeEventListener("message", listener);
        };
      },
      onExit: (handler) => {
        // Web Workers have no exit event; error/messageerror are the only death signals.
        const listener = (): void => {
          handler();
        };
        worker.addEventListener("error", listener);
        worker.addEventListener("messageerror", listener);
        return () => {
          worker.removeEventListener("error", listener);
          worker.removeEventListener("messageerror", listener);
        };
      },
      terminate: () => {
        worker.terminate();
      },
    };
  };

  const wallet = await connectKernel({
    spawn,
    passkey: options.passkey,
    ceremony,
  });

  // Page lifecycle: lock when the page has been hidden for 5 minutes, and on pagehide. A
  // BFCache-frozen page still runs the queued locked-event handler on restore, so the wallet
  // respawns then — terminating the worker directly would leave the wallet pointing at a dead
  // port.
  let hiddenTimer = 0;
  const onVisibility = (): void => {
    if (document.visibilityState === "hidden") {
      hiddenTimer = globalThis.setTimeout(() => {
        void bestEffort(async () => wallet.vault.lock());
      }, HIDDEN_LOCK_MS);
    } else {
      globalThis.clearTimeout(hiddenTimer);
    }
  };
  const onPageHide = (): void => {
    void bestEffort(async () => wallet.vault.lock());
  };
  document.addEventListener("visibilitychange", onVisibility);
  globalThis.addEventListener("pagehide", onPageHide);

  // Ask the browser to persist the vault once it exists — a denied request is fine.
  let persisted = false;
  const unsubscribe = wallet.subscribe(() => {
    if (!persisted && wallet.getSnapshot().vault !== "uninitialized") {
      persisted = true;
      unsubscribe();
      void bestEffort(async () => navigator.storage.persist());
    }
  });

  return {
    getSnapshot: () => wallet.getSnapshot(),
    subscribe: (listener) => wallet.subscribe(listener),
    vault: wallet.vault,
    wallets: wallet.wallets,
    nostr: wallet.nostr,
    exports: wallet.exports,
    dataKeys: wallet.dataKeys,
    destroy: async () => {
      document.removeEventListener("visibilitychange", onVisibility);
      globalThis.removeEventListener("pagehide", onPageHide);
      globalThis.clearTimeout(hiddenTimer);
      await wallet.destroy();
    },
  };
}

export { createWebAuthnPasskey } from "./passkey.ts";
export type { WebAuthnRp } from "./passkey.ts";
