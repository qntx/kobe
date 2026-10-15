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

/**
 * In-memory RecordStore for the Node host and kernel tests. Loads and commits deep-copy every
 * Uint8Array, so callers can never mutate stored state. `commit` applies ops to a clone and swaps
 * atomically: a failing `expect-uninitialized` leaves the store untouched.
 */
export function createMemoryStore(): RecordStore {
  let image: VaultImage = { meta: undefined, records: [], factors: [] };
  const listeners = new Set<() => void>();

  function apply(ops: ReadonlyArray<StoreOp>): VaultImage {
    let { meta } = image;
    let { records } = image;
    let { factors } = image;
    for (const op of ops) {
      switch (op.op) {
        case "expect-uninitialized":
          if (meta !== undefined || records.length > 0 || factors.length > 0) {
            throw new KernelError("integrity", "vault already initialized");
          }
          break;
        case "put-meta":
          meta = cloneMeta(op.meta);
          break;
        case "put-record":
          records = [
            ...records.filter(
              (record) => !(record.kind === op.record.kind && record.id === op.record.id),
            ),
            cloneRecord(op.record),
          ];
          break;
        case "delete-record":
          records = records.filter((record) => !(record.kind === op.kind && record.id === op.id));
          break;
        case "put-factor":
          factors = [
            ...factors.filter((factor) => factor.id !== op.factor.id),
            cloneFactor(op.factor),
          ];
          break;
        case "delete-factor":
          factors = factors.filter((factor) => factor.id !== op.id);
          break;
        case "clear":
          meta = undefined;
          records = [];
          factors = [];
          break;
      }
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
