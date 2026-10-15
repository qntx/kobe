/**
 * The Node host: `createNodeWallet` spawns the bundled kernel worker (dist/kernel.node.js) and
 * keeps the vault image — ciphertext + public headers, never secrets — in the main thread's
 * in-memory store, served to each worker over a MessageChannel. That is what lets a lock destroy
 * the whole worker without losing the vault.
 */
import { MessageChannel, Worker } from "node:worker_threads";

import { WalletError } from "@qntx/wallet";
import type { AutoLockPolicy, PasskeyConfig, Wallet } from "@qntx/wallet";
import { createMemoryStore } from "@qntx/wallet-kernel";
import { connectKernel } from "@qntx/wallet/host";
import type { MainPort, PasskeyCeremony } from "@qntx/wallet/host";
import type { ProtocolValue } from "@qntx/wallet/protocol";

import type { NodeWorkerData } from "../worker/node.ts";
import { serveStore } from "./store-server.ts";

export { createSoftwarePasskey } from "./software-passkey.ts";

export type NodeWalletOptions = {
  readonly passkey: PasskeyConfig;
  readonly autoLock: AutoLockPolicy;
  readonly authenticator?: PasskeyCeremony;
  /**
   * Test/debug hook: the worker file location and a spawn observer (count spawns, watch 'exit').
   * Defaults to the bundled dist/kernel.node.js next to this module.
   */
  readonly kernelUrl?: string | URL;
  readonly onSpawn?: (worker: Worker) => void;
};

export async function createNodeWallet(options: NodeWalletOptions): Promise<Wallet> {
  const { autoLock } = options;
  if (autoLock.platform !== "web") {
    throw new WalletError("invalid-input", "createNodeWallet accepts only the web autoLock policy");
  }
  // The host sends only the idle choice; the worker owns the maximum session duration.
  const workerData = { idleMinutes: autoLock.idleMinutes };
  const store = createMemoryStore(); // ciphertext + public headers only — safe in the main thread
  const kernelUrl = options.kernelUrl ?? new URL("kernel.node.js", import.meta.url);

  const spawn = (): MainPort => {
    const channel = new MessageChannel();
    const stopStore = serveStore(store, channel.port1);
    const worker = new Worker(kernelUrl, {
      workerData: { ...workerData, storePort: channel.port2 } satisfies NodeWorkerData,
      transferList: [channel.port2],
    });
    options.onSpawn?.(worker);
    return {
      post: (message: ProtocolValue, transfer: ArrayBuffer[]) => {
        worker.postMessage(message, transfer);
      },
      listen: (handler) => {
        const listener = (message: unknown) => {
          handler(message);
        };
        worker.on("message", listener);
        return () => {
          worker.off("message", listener);
        };
      },
      onExit: (handler) => {
        const listener = () => {
          handler();
        };
        worker.once("exit", listener);
        return () => {
          worker.off("exit", listener);
        };
      },
      terminate: () => {
        stopStore();
        void worker.terminate();
      },
    };
  };

  return connectKernel({
    spawn,
    passkey: options.passkey,
    ceremony: options.authenticator,
    setTimer: (delayMs, fn) => {
      const timer = setTimeout(fn, delayMs);
      return () => {
        clearTimeout(timer);
      };
    },
  });
}
