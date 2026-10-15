/**
 * RecordStore over a MessagePort RPC: the vault image (ciphertext + public headers) lives in the
 * main thread so a lock can destroy the whole worker without losing the vault. The main side pushes
 * a "changed" notice when some other writer committed; `watch` relays it to the kernel.
 */
import type { RecordStore, StoreOp, VaultImage } from "@qntx/wallet-kernel";

import type { StorePort, StoreReply, StoreRequest } from "../shared.ts";
import { assertVaultImage } from "../shared.ts";

export function createStoreClient(port: StorePort): RecordStore {
  let nextId = 1;
  const pending = new Map<number, (reply: StoreReply) => void>();
  const watchers = new Set<() => void>();

  port.listen((raw) => {
    // Internal channel between this package's two halves — a malformed message means the host
    // wiring is broken; dropping it is safer than guessing.
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
      return;
    }
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- internal wire shape; malformed payloads are dropped by the t-checks
    const reply = raw as StoreReply;
    if (reply.t === "changed") {
      for (const watcher of watchers) {
        watcher();
      }
      return;
    }
    if (reply.t === "loaded" || reply.t === "committed") {
      const resolve = pending.get(reply.id);
      if (resolve !== undefined) {
        pending.delete(reply.id);
        resolve(reply);
      }
    }
  });

  async function request(
    build: (id: number) => StoreRequest,
    pick: (reply: StoreReply) => VaultImage | undefined,
  ): Promise<VaultImage | undefined> {
    const id = nextId++;
    return new Promise((resolve, reject) => {
      pending.set(id, (reply) => {
        resolve(pick(reply));
      });
      try {
        port.post(build(id));
      } catch (error) {
        pending.delete(id);
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    });
  }

  return {
    async load(): Promise<VaultImage> {
      const reply = await request(
        (id) => ({ t: "load", id }),
        (r) => (r.t === "loaded" ? assertVaultImage(r.image) : undefined),
      );
      if (reply === undefined) {
        throw new Error("store: malformed load reply");
      }
      return reply;
    },
    async commit(ops: ReadonlyArray<StoreOp>): Promise<void> {
      await request(
        (id) => ({ t: "commit", id, ops }),
        () => undefined,
      );
    },
    watch(listener) {
      watchers.add(listener);
      return () => {
        watchers.delete(listener);
      };
    },
  };
}
