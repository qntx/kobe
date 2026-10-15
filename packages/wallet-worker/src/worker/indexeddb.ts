// oxlint-disable eslint/no-await-in-loop -- ops inside one transaction must issue sequentially; awaiting a pending request keeps the transaction alive
/**
 * The Web vault store, running inside the kernel worker: database `qntx-wallet` v1 with object
 * stores `records` (keyPath ["kind","id"]), `factors` (keyPath "id") and `meta` (key "vault").
 * Every commit runs inside the cross-tab Web Lock `qntx-wallet` so two tabs' workers serialize;
 * preconditions (`init`, `expect-revision`, counter ops on a missing meta) are checked inside that
 * transaction and abort it, so nothing is written. Other tabs' workers learn about commits through
 * `BroadcastChannel("qntx-wallet")` — the channel never echoes to the sender, and own commits are
 * already reloaded by the kernel's commit path.
 *
 * A `versionchange` (another tab opened a newer DB version) closes the connection and drops the
 * cached promise; the next load/commit reopens lazily — which either serves the newer layout or
 * fails `VersionError` → `unsupported`. An open request `blocked` longer than five seconds fails.
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
const DB_VERSION = 1; // the IndexedDB schema version — independent of the vault format
const LOCK_NAME = "qntx-wallet";
const CHANNEL_NAME = "qntx-wallet";
const META_KEY = "vault";
const STORES = ["records", "factors", "meta"] as const;
const BLOCKED_MS = 5000;

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

function openError(error: unknown): Error {
  // A stored DB whose version is newer than this build's is "unsupported", not corruption.
  if (error instanceof DOMException && error.name === "VersionError") {
    return new KernelError("unsupported", "indexeddb: vault database needs a newer build");
  }
  return error instanceof Error ? error : new Error("indexeddb open failed");
}

async function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    let settled = false;
    let blockedTimer: ReturnType<typeof setTimeout> | undefined;
    const settle = (fn: () => void): void => {
      if (settled) {
        return;
      }
      settled = true;
      if (blockedTimer !== undefined) {
        clearTimeout(blockedTimer);
      }
      fn();
    };
    request.addEventListener("upgradeneeded", () => {
      const db = request.result;
      db.createObjectStore("records", { keyPath: ["kind", "id"] });
      db.createObjectStore("factors", { keyPath: "id" });
      db.createObjectStore("meta");
    });
    request.addEventListener("blocked", () => {
      // Another connection refused to close on versionchange: give it five seconds, then
      // fail — a generic Error the kernel classifies as "unavailable" (retryable).
      blockedTimer = setTimeout(() => {
        settle(() => {
          reject(new Error("indexeddb: open request blocked"));
        });
      }, BLOCKED_MS);
    });
    request.addEventListener("success", () => {
      if (settled) {
        // The request succeeded after the blocked timeout already rejected: close the
        // late connection so it can never wedge a later upgrade.
        request.result.close();
        return;
      }
      settle(() => {
        resolve(request.result);
      });
    });
    request.addEventListener("error", () => {
      settle(() => {
        reject(openError(request.error));
      });
    });
  });
}

export function createIndexedDbStore(): RecordStore {
  let dbPromise: Promise<IDBDatabase> | undefined;
  let current: IDBDatabase | undefined;
  const channel = new BroadcastChannel(CHANNEL_NAME);

  // Lazily (re)opened connection: dropped on versionchange and after a failed open, so a
  // transient failure or a version bump never latches the store dead.
  const open = async (): Promise<IDBDatabase> => {
    const db = await openDb();
    current = db;
    db.addEventListener("versionchange", () => {
      db.close();
      if (current === db) {
        current = undefined;
        dbPromise = undefined;
      }
    });
    return db;
  };

  const database = async (): Promise<IDBDatabase> => {
    if (dbPromise === undefined) {
      const opening = open();
      dbPromise = opening;
      // oxlint-disable-next-line promise/prefer-await-to-then -- clears the cache only if this open is still the current one
      void opening.catch(() => {
        if (dbPromise === opening) {
          dbPromise = undefined;
        }
      });
    }
    return dbPromise;
  };

  return {
    async load(): Promise<VaultImage> {
      const db = await database();
      const tx = db.transaction(STORES, "readonly");
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
      let precondition: string | undefined;
      await navigator.locks.request(LOCK_NAME, async () => {
        const db = await database();
        const tx = db.transaction(STORES, "readwrite");
        const done = transactionDone(tx);
        const metaStore = tx.objectStore("meta");
        const records = tx.objectStore("records");
        const factors = tx.objectStore("factors");
        // Meta is read lazily once and carried in `metaValue`; mutations stage a put so the
        // revision bump (once per commit) always writes the final row.
        let metaLoaded = false;
        let metaValue: VaultMeta | undefined;
        let bump = false;
        let initialized = false;
        const readMeta = async (): Promise<VaultMeta | undefined> => {
          if (!metaLoaded) {
            metaValue = await requestValue<VaultMeta | undefined>(metaStore.get(META_KEY));
            metaLoaded = true;
          }
          return metaValue;
        };
        const writeMeta = (meta: VaultMeta): void => {
          metaValue = meta;
          metaStore.put(meta, META_KEY);
        };
        const requireMeta = async (): Promise<VaultMeta | undefined> => {
          const meta = await readMeta();
          if (meta === undefined) {
            precondition = "vault is not initialized";
            tx.abort();
          }
          return meta;
        };
        for (const op of ops) {
          switch (op.op) {
            case "init": {
              const [meta, recordCount, factorCount] = await Promise.all([
                readMeta(),
                requestValue<number>(records.count()),
                requestValue<number>(factors.count()),
              ]);
              if (meta !== undefined || recordCount > 0 || factorCount > 0) {
                precondition = "vault already initialized";
                tx.abort();
              } else {
                writeMeta(op.meta); // init writes the meta verbatim — no revision bump
                initialized = true;
              }
              break;
            }
            case "expect-revision": {
              const meta = await readMeta();
              if (meta === undefined || meta.revision !== op.revision) {
                precondition = "vault changed underneath";
                tx.abort();
              }
              break;
            }
            case "set-key-id": {
              const meta = await requireMeta();
              if (meta !== undefined) {
                writeMeta({ ...meta, keyId: op.keyId });
                bump = true;
              }
              break;
            }
            case "record-failure": {
              const meta = await requireMeta();
              if (meta !== undefined) {
                writeMeta({
                  ...meta,
                  failedAttempts: meta.failedAttempts + 1,
                  lastFailureAt: op.at,
                });
              }
              break;
            }
            case "reset-failures": {
              const meta = await requireMeta();
              if (meta !== undefined) {
                writeMeta({ ...meta, failedAttempts: 0, lastFailureAt: 0 });
              }
              break;
            }
            case "put-record":
              records.put(op.record);
              bump = true;
              break;
            case "delete-record":
              records.delete([op.kind, op.id]);
              bump = true;
              break;
            case "put-factor":
              factors.put(op.factor);
              bump = true;
              break;
            case "delete-factor":
              factors.delete(op.id);
              bump = true;
              break;
            case "clear":
              for (const name of STORES) {
                tx.objectStore(name).clear();
              }
              break;
          }
          if (precondition !== undefined) {
            break;
          }
        }
        if (precondition === undefined && bump && !initialized) {
          const meta = await readMeta();
          if (meta !== undefined) {
            writeMeta({ ...meta, revision: meta.revision + 1 });
          }
        }
        try {
          await done;
        } catch (error) {
          if (precondition !== undefined) {
            throw new KernelError("conflict", `vault store: ${precondition}`);
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
