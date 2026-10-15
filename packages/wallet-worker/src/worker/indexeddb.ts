// oxlint-disable eslint/no-await-in-loop -- ops inside one transaction must issue sequentially; awaiting a pending request keeps the transaction alive
/**
 * The Web vault store, running inside the kernel worker: database `qntx-wallet` v1 with object
 * stores `records` (keyPath ["kind","id"]), `factors` (keyPath "id") and `meta` (key "vault").
 * Every commit runs inside the cross-tab Web Lock `qntx-wallet` so two tabs' workers serialize;
 * `expect-uninitialized` is checked inside that transaction and aborts it, so nothing is written.
 * Other tabs' workers learn about commits through `BroadcastChannel("qntx-wallet")` — the channel
 * never echoes to the sender, and own commits are already reloaded by the kernel's commit path.
 */
import { KernelError } from "@qntx/wallet-kernel";
import type {
  RecordStore,
  StoredFactor,
  StoredRecord,
  StoreOp,
  VaultImage,
  VaultMeta,
} from "@qntx/wallet-kernel";

import { assertVaultImage } from "../shared.ts";

const DB_NAME = "qntx-wallet";
const LOCK_NAME = "qntx-wallet";
const CHANNEL_NAME = "qntx-wallet";
const META_KEY = "vault";
const STORES = ["records", "factors", "meta"] as const;

// IDB request results are `any`; the row shape is fixed by this store's writers, so the type
// argument is asserted once here instead of at every call site.
async function requestValue<T>(request: IDBRequest): Promise<T> {
  return new Promise((resolve, reject) => {
    request.addEventListener("success", () => {
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- see above
      resolve(request.result as T);
    });
    request.addEventListener("error", () => {
      reject(
        request.error instanceof Error ? request.error : new Error("indexeddb request failed"),
      );
    });
  });
}

async function transactionDone(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.addEventListener("complete", () => {
      resolve();
    });
    const fail = (): void => {
      reject(tx.error instanceof Error ? tx.error : new Error("indexeddb transaction failed"));
    };
    tx.addEventListener("error", fail);
    tx.addEventListener("abort", fail);
  });
}

async function openDb(): Promise<IDBDatabase> {
  const request = indexedDB.open(DB_NAME, 1);
  request.addEventListener("upgradeneeded", () => {
    const db = request.result;
    db.createObjectStore("records", { keyPath: ["kind", "id"] });
    db.createObjectStore("factors", { keyPath: "id" });
    db.createObjectStore("meta");
  });
  return requestValue(request);
}

export function createIndexedDbStore(): RecordStore {
  const db = openDb();
  const channel = new BroadcastChannel(CHANNEL_NAME);

  return {
    async load(): Promise<VaultImage> {
      const database = await db;
      const tx = database.transaction(STORES, "readonly");
      const [meta, records, factors] = await Promise.all([
        requestValue<VaultMeta | undefined>(tx.objectStore("meta").get(META_KEY)),
        requestValue<StoredRecord[]>(tx.objectStore("records").getAll()),
        requestValue<StoredFactor[]>(tx.objectStore("factors").getAll()),
      ]);
      // The same-origin main thread can write anything here: validate every row structurally
      // so a malformed store fails "integrity" instead of crashing the worker on open.
      return assertVaultImage({ meta, records, factors });
    },

    async commit(ops: ReadonlyArray<StoreOp>): Promise<void> {
      let preconditionFailed = false;
      await navigator.locks.request(LOCK_NAME, async () => {
        const database = await db;
        const tx = database.transaction(STORES, "readwrite");
        const done = transactionDone(tx);
        const metaStore = tx.objectStore("meta");
        const records = tx.objectStore("records");
        const factors = tx.objectStore("factors");
        for (const op of ops) {
          switch (op.op) {
            case "expect-uninitialized": {
              const [meta, recordCount, factorCount] = await Promise.all([
                requestValue<VaultMeta | undefined>(metaStore.get(META_KEY)),
                requestValue<number>(records.count()),
                requestValue<number>(factors.count()),
              ]);
              if (meta !== undefined || recordCount > 0 || factorCount > 0) {
                preconditionFailed = true;
                tx.abort();
              }
              break;
            }
            case "put-meta":
              metaStore.put(op.meta, META_KEY);
              break;
            case "put-record":
              records.put(op.record);
              break;
            case "delete-record":
              records.delete([op.kind, op.id]);
              break;
            case "put-factor":
              factors.put(op.factor);
              break;
            case "delete-factor":
              factors.delete(op.id);
              break;
            case "clear":
              for (const name of STORES) {
                tx.objectStore(name).clear();
              }
              break;
          }
          if (preconditionFailed) {
            break;
          }
        }
        try {
          await done;
        } catch (error) {
          if (preconditionFailed) {
            throw new KernelError("integrity", "vault already initialized");
          }
          throw error;
        }
      });
      // Delivered to the OTHER tabs' workers; the sender never receives its own broadcast.
      // oxlint-disable-next-line unicorn/require-post-message-target-origin -- BroadcastChannel takes no targetOrigin
      channel.postMessage("changed");
    },

    watch(listener: () => void): () => void {
      const onMessage = (): void => {
        listener();
      };
      channel.addEventListener("message", onMessage);
      return () => {
        channel.removeEventListener("message", onMessage);
      };
    },
  };
}
