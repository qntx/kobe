/**
 * The browser kernel worker, bundled to dist/kernel.worker.js by `bun build`. All platform
 * capabilities are wired here: subtle PBKDF2, the IndexedDB vault store, timers through
 * platform.setTimer, and the session policy from the host's init message — the kernel does not
 * start until a strictly-validated init arrives. The kernel itself stays platform-neutral.
 */
import { startKernel } from "@qntx/wallet-kernel";
import type { KernelPlatform, Port } from "@qntx/wallet-kernel";

import { isBrowserWorkerInit } from "../shared.ts";
import { createIndexedDbStore } from "./indexeddb.ts";
import { subtlePbkdf2 } from "./subtle.ts";

const onInit = (event: MessageEvent<unknown>): void => {
  const { data } = event;
  if (!isBrowserWorkerInit(data)) {
    return; // not the init message — the kernel must not start without a valid policy
  }
  removeEventListener("message", onInit);

  const platform: KernelPlatform = {
    random: (length) => crypto.getRandomValues(new Uint8Array(length)),
    now: () => Date.now(),
    setTimer: (delayMs, fn) => {
      const timer = setTimeout(fn, delayMs);
      return () => {
        clearTimeout(timer);
      };
    },
    pbkdf2: subtlePbkdf2,
    store: createIndexedDbStore(),
    policy: { idleMs: data.idleMs, maxSessionMs: data.maxSessionMs },
  };

  const port: Port = {
    post: (message, transfer) => {
      postMessage(message, transfer);
    },
    listen: (handler) => {
      const listener = (messageEvent: MessageEvent<unknown>): void => {
        handler(messageEvent.data);
      };
      addEventListener("message", listener);
      return () => {
        removeEventListener("message", listener);
      };
    },
  };

  startKernel(platform, port);
};

addEventListener("message", onInit);
