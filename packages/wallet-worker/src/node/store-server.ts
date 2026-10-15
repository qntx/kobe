/**
 * Main-side half of the store RPC: serves the shared in-memory RecordStore to the worker and pushes
 * "changed" notices for commits that did NOT come through this port (the kernel's own commits must
 * not echo back as external changes).
 */
import type { MessagePort } from "node:worker_threads";

import { KernelError } from "@qntx/wallet-kernel";
import type { KernelErrorCode, RecordStore } from "@qntx/wallet-kernel";

import type { StoreReply, StoreRequest } from "../shared.ts";
import { encodeImage } from "../shared.ts";

// Internal wire between this package's two halves — malformed payloads get dropped.
function isStoreRequest(raw: unknown): raw is StoreRequest {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return false;
  }
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- narrowed to a plain object above
  const request = raw as Record<string, unknown>;
  if (typeof request["id"] !== "number") {
    return false;
  }
  return request["t"] === "load" || (request["t"] === "commit" && Array.isArray(request["ops"]));
}

export function serveStore(store: RecordStore, port: MessagePort): () => void {
  let ownCommits = 0;

  const post = (reply: StoreReply): void => {
    port.postMessage(reply);
  };

  // A failed load/commit replies "failed" with the KernelError code (or "unavailable" for a
  // non-kernel failure) — a request that hangs would deadlock the kernel's sequential queue.
  const failed = (id: number, error: unknown): void => {
    const code: KernelErrorCode = error instanceof KernelError ? error.code : "unavailable";
    post({ t: "failed", id, code });
  };

  const answer = async (request: StoreRequest): Promise<void> => {
    if (request.t === "load") {
      try {
        post({ t: "loaded", id: request.id, image: encodeImage(await store.load()) });
      } catch (error) {
        failed(request.id, error);
      }
      return;
    }
    ownCommits++;
    try {
      await store.commit(request.ops);
    } catch (error) {
      ownCommits--; // a failed commit fires no watch — do not eat the next external notice
      failed(request.id, error);
      return;
    }
    post({ t: "committed", id: request.id });
  };

  const onMessage = (raw: unknown): void => {
    if (!isStoreRequest(raw)) {
      return;
    }
    void (async (): Promise<void> => {
      try {
        await answer(raw);
      } catch {
        // A dead worker cannot be answered; the exit path handles it.
      }
    })();
  };

  const unwatch = store.watch(() => {
    if (ownCommits > 0) {
      ownCommits--;
      return;
    }
    post({ t: "changed" });
  });

  port.on("message", onMessage);
  port.start();

  return () => {
    unwatch();
    port.off("message", onMessage);
    port.close();
  };
}
