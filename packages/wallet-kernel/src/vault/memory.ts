import { KernelError } from "../errors.ts";
import type {
  RecordStore,
  StoredFactor,
  StoredRecord,
  StoreOp,
  VaultImage,
  VaultMeta,
} from "./store.ts";

function cloneRecord(record: StoredRecord): StoredRecord {
  return { ...record, sealed: Uint8Array.from(record.sealed) };
}

function cloneFactor(factor: StoredFactor): StoredFactor {
  return { ...factor, sealed: Uint8Array.from(factor.sealed) };
}

function cloneMeta(meta: VaultMeta): VaultMeta {
  return { ...meta };
}

function cloneImage(image: VaultImage): VaultImage {
  return {
    meta: image.meta === undefined ? undefined : cloneMeta(image.meta),
    records: image.records.map(cloneRecord),
    factors: image.factors.map(cloneFactor),
  };
}

function conflict(message: string): KernelError {
  return new KernelError("conflict", `vault store: ${message}`);
}

function requireMeta(meta: VaultMeta | undefined): VaultMeta {
  if (meta === undefined) {
    throw conflict("vault is not initialized");
  }
  return meta;
}

/**
 * In-memory RecordStore for the Node host and kernel tests. Loads and commits deep-copy every
 * Uint8Array, so callers can never mutate stored state. `commit` applies ops to a clone and swaps
 * atomically: a failing precondition (`init`, `expect-revision`, a counter op on an empty store)
 * leaves the store untouched. Content ops bump `meta.revision` once per commit; an `init` commit
 * writes its meta verbatim (revision stays as the initializer set it).
 */
export function createMemoryStore(): RecordStore {
  let image: VaultImage = { meta: undefined, records: [], factors: [] };
  const listeners = new Set<() => void>();

  function apply(ops: ReadonlyArray<StoreOp>): VaultImage {
    let { meta } = image;
    let { records } = image;
    let { factors } = image;
    let bump = false;
    let initialized = false;
    for (const op of ops) {
      switch (op.op) {
        case "init":
          if (meta !== undefined || records.length > 0 || factors.length > 0) {
            throw conflict("vault already initialized");
          }
          meta = cloneMeta(op.meta);
          initialized = true;
          break;
        case "expect-revision":
          if (meta === undefined || meta.revision !== op.revision) {
            throw conflict("vault changed underneath");
          }
          break;
        case "set-key-id":
          meta = { ...requireMeta(meta), keyId: op.keyId };
          bump = true;
          break;
        case "record-failure": {
          const current = requireMeta(meta);
          meta = {
            ...current,
            failedAttempts: current.failedAttempts + 1,
            lastFailureAt: op.at,
          };
          break;
        }
        case "reset-failures":
          meta = { ...requireMeta(meta), failedAttempts: 0, lastFailureAt: 0 };
          break;
        case "put-record":
          records = [
            ...records.filter(
              (record) => !(record.kind === op.record.kind && record.id === op.record.id),
            ),
            cloneRecord(op.record),
          ];
          bump = true;
          break;
        case "delete-record":
          records = records.filter((record) => !(record.kind === op.kind && record.id === op.id));
          bump = true;
          break;
        case "put-factor":
          factors = [
            ...factors.filter((factor) => factor.id !== op.factor.id),
            cloneFactor(op.factor),
          ];
          bump = true;
          break;
        case "delete-factor":
          factors = factors.filter((factor) => factor.id !== op.id);
          bump = true;
          break;
        case "clear":
          meta = undefined;
          records = [];
          factors = [];
          break;
      }
    }
    if (bump && !initialized && meta !== undefined) {
      meta = { ...meta, revision: meta.revision + 1 };
    }
    return { meta, records, factors };
  }

  return {
    async load() {
      return cloneImage(image);
    },
    async commit(ops) {
      const next = apply(ops);
      image = next;
      for (const listener of listeners) {
        listener();
      }
    },
    watch(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
  };
}
