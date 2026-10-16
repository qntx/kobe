/**
 * The Web host: `createWebWallet` spawns the bundled kernel worker (dist/kernel.worker.js) whose
 * vault lives in the worker's own IndexedDB. Lock destroys the worker; the vault survives in
 * IndexedDB, so the respawned worker reloads it. `pagehide` locks immediately; the idle timer is
 * refreshed by user-presence signals, not request traffic. The WebAuthn ceremony runs on the main
 * thread.
 */
import { WalletError } from "@qntx/wallet";
import type { Wallet, WalletOptions } from "@qntx/wallet";
import { connectKernel } from "@qntx/wallet/host";
import type { MainPort } from "@qntx/wallet/host";
import type { ProtocolValue } from "@qntx/wallet/protocol";

import type { BrowserWorkerInit } from "../shared.ts";
import { createWebAuthnPasskey } from "./passkey.ts";

const LISTENER_OPTIONS = { capture: true, passive: true };
const ACTIVITY_EVENTS = ["pointerdown", "pointermove", "keydown", "wheel", "touchstart"];

/**
 * The browser's user-presence source: direct input on the page, or returning to a visible tab.
 * Capture-phase passive listeners do a single boolean check per event — high-frequency signals
 * (scroll, pointermove) cost nothing. Returns the unsubscribe the wallet owns.
 */
function subscribePresence(onActivity: () => void): () => void {
  for (const type of ACTIVITY_EVENTS) {
    globalThis.addEventListener(type, onActivity, LISTENER_OPTIONS);
  }
  const onVisible = (): void => {
    if (document.visibilityState === "visible") {
      onActivity();
    }
  };
  document.addEventListener("visibilitychange", onVisible);
  return () => {
    for (const type of ACTIVITY_EVENTS) {
      globalThis.removeEventListener(type, onActivity, LISTENER_OPTIONS);
    }
    document.removeEventListener("visibilitychange", onVisible);
  };
}

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
  // The page sends only the idle choice; the worker owns the maximum session duration.
  const init: BrowserWorkerInit = { t: "init", idleMinutes: autoLock.idleMinutes };
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
    setTimer: (delayMs, fn) => {
      const timer = globalThis.setTimeout(fn, delayMs);
      return () => {
        globalThis.clearTimeout(timer);
      };
    },
    presence: subscribePresence,
    onDestroy: () => {
      globalThis.removeEventListener("pagehide", onPageHide);
    },
  });

  // Page lifecycle: lock on pagehide. A BFCache-frozen page still runs the queued locked-event
  // handler on restore, so the wallet respawns then — terminating the worker directly would
  // leave the wallet pointing at a dead port.
  const onPageHide = (): void => {
    void bestEffort(async () => wallet.vault.lock());
  };
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

  return wallet;
}

export { createWebAuthnPasskey } from "./passkey.ts";
export type { WebAuthnRp } from "./passkey.ts";
