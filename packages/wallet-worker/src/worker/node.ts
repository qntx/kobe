/**
 * The Node kernel worker, bundled to dist/kernel.node.js by `bun build`. All platform capabilities
 * are wired here: subtle PBKDF2, the store RPC over the transferred MessagePort, timers through
 * platform.setTimer, policy from workerData. The kernel itself stays platform-neutral.
 */
import { parentPort, workerData } from "node:worker_threads";
import type { MessagePort } from "node:worker_threads";

import { startKernel } from "@qntx/wallet-kernel";
import type { KernelPlatform, Port } from "@qntx/wallet-kernel";

import { MAX_SESSION_MS, idleMsOf, isNodeWorkerData } from "../shared.ts";
import { createStoreClient } from "./store-client.ts";
import { subtlePbkdf2 } from "./subtle.ts";

export type NodeWorkerData = {
  readonly idleMinutes: 5 | 15 | 60;
  readonly storePort: MessagePort;
};

const main = parentPort;
if (main === null) {
  throw new Error("kernel.node.js must run inside a worker_threads Worker");
}
if (!isNodeWorkerData(workerData)) {
  throw new Error("kernel.node.js received invalid workerData");
}
const data: NodeWorkerData = {
  idleMinutes: workerData.idleMinutes,
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- isNodeWorkerData narrowed the shape; MessagePort is the node type
  storePort: workerData.storePort as MessagePort,
};

data.storePort.start();

const platform: KernelPlatform = {
  random: (length) => crypto.getRandomValues(new Uint8Array(length)),
  now: () => Date.now(),
  elapsed: () => performance.now(),
  setTimer: (delayMs, fn) => {
    const timer = setTimeout(fn, delayMs);
    return () => {
      clearTimeout(timer);
    };
  },
  pbkdf2: subtlePbkdf2,
  store: createStoreClient({
    post: (message) => {
      // oxlint-disable-next-line unicorn/require-post-message-target-origin -- worker_threads port, not window.postMessage
      data.storePort.postMessage(message);
    },
    listen: (handler) => {
      const listener = (message: unknown) => {
        handler(message);
      };
      data.storePort.on("message", listener);
      return () => {
        data.storePort.off("message", listener);
      };
    },
  }),
  // Session limits are owned here, not by the host: idle from the validated workerData, the
  // fixed maximum, and the scrypt ceiling for this platform.
  policy: { idleMs: idleMsOf(data.idleMinutes), maxSessionMs: MAX_SESSION_MS, maxScryptLogN: 20 },
};

const port: Port = {
  post: (message, transfer) => {
    main.postMessage(message, transfer);
  },
  listen: (handler) => {
    const listener = (message: unknown) => {
      handler(message);
    };
    main.on("message", listener);
    return () => {
      main.off("message", listener);
    };
  },
};

startKernel(platform, port);
