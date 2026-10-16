import { describe, expect, it, vi } from "vite-plus/test";

import { createMemoryStore } from "../src/vault/memory.ts";
import type { StoredFactor, StoredRecord, VaultImage, VaultMeta } from "../src/vault/store.ts";
import { VAULT_FORMAT } from "../src/vault/store.ts";

const empty: VaultImage = { meta: undefined, records: [], factors: [] };

const meta: VaultMeta = {
  format: VAULT_FORMAT,
  revision: 1,
  keyId: "a".repeat(32),
  failedAttempts: 0,
  lastFailureAt: 0,
};

const record: StoredRecord = {
  kind: "entropy",
  id: "aa",
  sealed: new Uint8Array([1, 2, 3]),
  header:
    '{"walletId":"6e0d11a50c03aa4f","origin":"mnemonic","words":12,"backup":"none","createdAt":0}',
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

  it("init applies ops atomically and watch fires", async () => {
    const store = createMemoryStore();
    const watcher = vi.fn();
    store.watch(watcher);
    await store.commit([
      { op: "init", meta },
      { op: "put-record", record },
    ]);
    expect(watcher).toHaveBeenCalledTimes(1);
    const loaded = await store.load();
    // init writes the meta verbatim — the content op in the same commit does not bump it
    expect(loaded.meta).toStrictEqual(meta);
    expect(loaded.records).toStrictEqual([record]);
  });

  it("a failing init writes nothing", async () => {
    const store = createMemoryStore();
    await store.commit([{ op: "init", meta }]);
    const before = await store.load();
    await expect(
      store.commit([
        { op: "init", meta },
        { op: "put-record", record },
      ]),
    ).rejects.toMatchObject({ code: "conflict" });
    await expect(store.load()).resolves.toStrictEqual(before);
  });

  it("content commits bump the revision by one", async () => {
    const store = createMemoryStore();
    await store.commit([{ op: "init", meta }]);
    await store.commit([
      { op: "expect-revision", revision: 1 },
      { op: "put-record", record },
    ]);
    await store.commit([{ op: "put-factor", factor }]);
    const loaded = await store.load();
    expect(loaded.meta).toStrictEqual({ ...meta, revision: 3 });
  });

  it("expect-revision mismatch fails with conflict and writes nothing", async () => {
    const store = createMemoryStore();
    await store.commit([
      { op: "init", meta },
      { op: "put-factor", factor },
    ]);
    const before = await store.load();
    await expect(
      store.commit([
        { op: "expect-revision", revision: 99 },
        { op: "delete-factor", id: "bb" },
      ]),
    ).rejects.toMatchObject({ code: "conflict" });
    await expect(store.load()).resolves.toStrictEqual(before);
  });

  it("counter ops do not bump the revision", async () => {
    const store = createMemoryStore();
    await store.commit([{ op: "init", meta }]);
    await store.commit([{ op: "record-failure", at: 123 }]);
    await store.commit([{ op: "record-failure", at: 456 }]);
    const loaded = await store.load();
    expect(loaded.meta).toStrictEqual({ ...meta, failedAttempts: 2, lastFailureAt: 456 });
    await store.commit([{ op: "reset-failures" }]);
    const cleared = await store.load();
    expect(cleared.meta).toStrictEqual(meta);
  });

  it("counter ops on an empty store fail with conflict", async () => {
    const store = createMemoryStore();
    await expect(store.commit([{ op: "record-failure", at: 1 }])).rejects.toMatchObject({
      code: "conflict",
    });
    await expect(store.commit([{ op: "reset-failures" }])).rejects.toMatchObject({
      code: "conflict",
    });
  });

  it("set-key-id changes keyId and bumps the revision", async () => {
    const store = createMemoryStore();
    await store.commit([{ op: "init", meta }]);
    await store.commit([{ op: "set-key-id", keyId: "b".repeat(32) }]);
    const loaded = await store.load();
    expect(loaded.meta).toStrictEqual({ ...meta, keyId: "b".repeat(32), revision: 2 });
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
      { op: "init", meta },
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
