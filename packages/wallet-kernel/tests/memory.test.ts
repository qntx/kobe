import { describe, expect, it, vi } from "vite-plus/test";

import { createMemoryStore } from "../src/vault/memory.ts";
import type { StoredFactor, StoredRecord, VaultImage, VaultMeta } from "../src/vault/store.ts";

const empty: VaultImage = { meta: undefined, records: [], factors: [] };

const meta: VaultMeta = { format: 1, failedAttempts: 0, retryAt: 0 };

const record: StoredRecord = {
  kind: "entropy",
  id: "aa",
  sealed: new Uint8Array([1, 2, 3]),
  header:
    '{"walletId":"6e0d11a50c03aa4f","origin":"mnemonic","words":12,"backedUp":false,"createdAt":0}',
};

const factor: StoredFactor = {
  kind: "password",
  id: "bb",
  sealed: new Uint8Array([9]),
  header: "{}",
};

describe("memory store", () => {
  it("returns an empty image before any commit", async () => {
    const store = createMemoryStore();
    await expect(store.load()).resolves.toStrictEqual(empty);
  });

  it("commit applies ops atomically and watch fires", async () => {
    const store = createMemoryStore();
    const watcher = vi.fn();
    store.watch(watcher);
    await store.commit([
      { op: "expect-uninitialized" },
      { op: "put-meta", meta },
      { op: "put-record", record },
    ]);
    expect(watcher).toHaveBeenCalledTimes(1);
    const loaded = await store.load();
    expect(loaded.meta).toStrictEqual(meta);
    expect(loaded.records).toStrictEqual([record]);
  });

  it("a failing expect-uninitialized writes nothing", async () => {
    const store = createMemoryStore();
    await store.commit([{ op: "put-meta", meta }]);
    const before = await store.load();
    await expect(
      store.commit([{ op: "expect-uninitialized" }, { op: "put-record", record }]),
    ).rejects.toMatchObject({ code: "integrity" });
    await expect(store.load()).resolves.toStrictEqual(before);
  });

  it("load returns copies, not the stored buffers", async () => {
    const store = createMemoryStore();
    await store.commit([{ op: "put-record", record }]);
    const loaded = await store.load();
    loaded.records[0]!.sealed.fill(0);
    const reloaded = await store.load();
    expect(reloaded.records[0]!.sealed).toStrictEqual(new Uint8Array([1, 2, 3]));
  });

  it("committing a record does not alias the caller's buffer", async () => {
    const store = createMemoryStore();
    const caller = { ...record, sealed: new Uint8Array([1, 2, 3]) };
    await store.commit([{ op: "put-record", record: caller }]);
    caller.sealed.fill(0);
    const loaded = await store.load();
    expect(loaded.records[0]!.sealed).toStrictEqual(new Uint8Array([1, 2, 3]));
  });

  it("delete-record, delete-factor and clear work", async () => {
    const store = createMemoryStore();
    await store.commit([
      { op: "put-meta", meta },
      { op: "put-record", record },
      { op: "put-factor", factor },
    ]);
    await store.commit([{ op: "delete-record", kind: "entropy", id: "aa" }]);
    const afterDeleteRecord = await store.load();
    expect(afterDeleteRecord.records).toStrictEqual([]);
    await store.commit([{ op: "delete-factor", id: "bb" }]);
    const afterDeleteFactor = await store.load();
    expect(afterDeleteFactor.factors).toStrictEqual([]);
    await store.commit([{ op: "clear" }]);
    await expect(store.load()).resolves.toStrictEqual(empty);
  });
});
