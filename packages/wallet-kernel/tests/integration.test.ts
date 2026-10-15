import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vite-plus/test";

import { Keys, KeysSigner, npubEncode, verifyEvent } from "@qntx/nostr";
import type { Event } from "@qntx/nostr";
import { decode as nip19Decode } from "@qntx/nostr/nips/nip19";
import { decrypt as nip49Decrypt } from "@qntx/nostr/nips/nip49";
import { createRumor, wrap as nip59Wrap } from "@qntx/nostr/nips/nip59";
import type { KernelEvent, ProtocolValue, WalletErrorCode } from "@qntx/wallet/protocol";
import type { FactorInfo, StatusPayload as StatusT } from "@qntx/wallet/types";

import { KernelError } from "../src/errors.ts";
import { createMemoryStore } from "../src/vault/memory.ts";
import type { RecordStore, VaultMeta } from "../src/vault/store.ts";
import { VAULT_FORMAT } from "../src/vault/store.ts";
import type { Harness, KernelResponse } from "./harness.ts";
import { createHarness, nonEchoing } from "./harness.ts";
import { loadVectors } from "./helpers.ts";

const passkeyVector = loadVectors("passkey.json") as {
  vector: {
    prf: string;
    mnemonic: string;
    publicKey: string;
    privateKey: string;
    walletId: string;
  };
};
const nip06 = loadVectors("nip06.json") as {
  vectors: Array<{ mnemonic: string; privateKey: string; publicKey: string; nsec: string }>;
};

const PRF_WALLET = hexToBytes(passkeyVector.vector.prf);
const PRF_VAULT = hexToBytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
const CREDENTIAL_ID = utf8ToBytes("credential-1");
const PASSWORD = utf8ToBytes("correct horse battery");

function ok(response: KernelResponse): ProtocolValue {
  if ("err" in response) {
    throw new Error(`expected ok, got ${JSON.stringify(response.err)}`);
  }
  return response.ok;
}

function errPayload(response: KernelResponse): { code: WalletErrorCode; retryAt?: number } {
  if (!("err" in response)) {
    throw new Error("expected err, got ok");
  }
  return response.err;
}

function errCode(response: KernelResponse): WalletErrorCode {
  return errPayload(response).code;
}

/** A store whose `load` rejects while `broken()` holds — used to drive the poisoned-store path. */
function failingLoad(store: RecordStore, broken: () => boolean): RecordStore["load"] {
  return async () => {
    if (broken()) {
      throw new KernelError("integrity", "corrupt store");
    }
    return store.load();
  };
}

function field(value: ProtocolValue, key: string): ProtocolValue {
  // Arrays and Uint8Array both carry Symbol.iterator; plain records do not.
  if (typeof value !== "object" || value === null || Symbol.iterator in value) {
    throw new Error("expected object");
  }
  const v = value[key];
  if (v === undefined) {
    throw new Error(`missing field ${key}`);
  }
  return v;
}

function strField(value: ProtocolValue, key: string): string {
  const v = field(value, key);
  if (typeof v !== "string") {
    throw new TypeError(`field ${key}: not a string`);
  }
  return v;
}

function bytesField(value: ProtocolValue, key: string): Uint8Array {
  const v = field(value, key);
  if (!(v instanceof Uint8Array)) {
    throw new Error(`field ${key}: not bytes`);
  }
  return v;
}

function listField(value: ProtocolValue, key: string): ReadonlyArray<ProtocolValue> {
  const v = field(value, key);
  if (!Array.isArray(v)) {
    throw new TypeError(`field ${key}: not an array`);
  }
  return v;
}

function numField(value: ProtocolValue, key: string): number {
  const v = field(value, key);
  if (typeof v !== "number") {
    throw new TypeError(`field ${key}: not a number`);
  }
  return v;
}

function intList(value: ProtocolValue, key: string): number[] {
  return listField(value, key).map(numOf);
}

function numOf(v: ProtocolValue): number {
  if (typeof v !== "number") {
    throw new TypeError("not a number");
  }
  return v;
}

function must<T>(value: T | undefined): T {
  if (value === undefined) {
    throw new Error("expected a defined value");
  }
  return value;
}

function factorId(factor: FactorInfo | undefined): string {
  if (factor === undefined || factor.kind === "hardware") {
    throw new Error("expected a factor id");
  }
  return factor.id;
}

function lockReasons(events: ReadonlyArray<KernelEvent>): string[] {
  return events.flatMap((e) => (e.event === "locked" ? [e.reason] : []));
}

function nsecData(decoded: ReturnType<typeof nip19Decode>): Uint8Array {
  if (decoded.type !== "nsec") {
    throw new Error(`expected nsec, got ${decoded.type}`);
  }
  return decoded.data;
}

function lastStatus(h: ReturnType<typeof createHarness>): StatusT {
  for (let i = h.events.length - 1; i >= 0; i--) {
    const event = h.events[i];
    if (event !== undefined && event.event === "status") {
      return event.status;
    }
  }
  throw new Error("no status event yet");
}

/** The stored meta row, asserted present. */
async function storedMeta(store: RecordStore): Promise<VaultMeta> {
  const image = await store.load();
  return must(image.meta);
}

/** The persisted wrong-password counter. */
async function storedFailedAttempts(store: RecordStore): Promise<number> {
  const meta = await storedMeta(store);
  return meta.failedAttempts;
}

/** "ok" or the error code — lifted out so test bodies carry no conditionals. */
function codeOf(response: KernelResponse): string {
  return "err" in response ? response.err.code : "ok";
}

/** A store wrapper that fails every `load` while `broken` holds true. */
function flakyLoad(store: RecordStore, broken: { current: boolean }): RecordStore {
  return {
    ...store,
    load: async () => {
      if (broken.current) {
        throw new Error("transient io");
      }
      return store.load();
    },
  };
}

/** A store wrapper that fails every `commit` while `broken` holds true. */
function flakyCommit(store: RecordStore, broken: { current: boolean }): RecordStore {
  return {
    ...store,
    commit: async (ops) => {
      if (broken.current) {
        throw new Error("quota exceeded");
      }
      return store.commit(ops);
    },
  };
}

/** A format-2 meta row as written by a vault init, with overridable fields for health tests. */
function metaOf(overrides?: Partial<VaultMeta>): VaultMeta {
  return {
    format: VAULT_FORMAT,
    revision: 1,
    keyId: "ab".repeat(16),
    failedAttempts: 0,
    lastFailureAt: 0,
    ...overrides,
  };
}

// A factory, not a constant: the kernel wipes a factor's secret bytes while consuming them, so a
// wire factor must never be shared between calls.
function passkeyFactor(): { kind: "passkey"; credentialId: Uint8Array; prf: Uint8Array } {
  return {
    kind: "passkey",
    credentialId: new Uint8Array(CREDENTIAL_ID),
    prf: new Uint8Array(PRF_VAULT),
  };
}

/**
 * A fresh kernel over the same store — what a host-side lock + worker respawn looks like from the
 * kernel's side. The old harness stays subscribed (a terminated worker's ghost) but is inert for
 * the test's purposes.
 */
function respawn(h: Harness, wrapStore?: (store: RecordStore) => RecordStore): Harness {
  return createHarness({ store: h.store, wrapStore });
}

async function createPasskeyWallet(h: ReturnType<typeof createHarness>) {
  const res = ok(
    await h.call("wallet.createWithPasskey", {
      credentialId: CREDENTIAL_ID,
      prfWallet: new Uint8Array(PRF_WALLET),
      factor: { kind: "passkey", credentialId: CREDENTIAL_ID, prf: new Uint8Array(PRF_VAULT) },
    }),
  );
  return {
    session: strField(res, "session"),
    walletId: strField(field(res, "wallet"), "walletId"),
  };
}

/** Creation no longer derives keys: tests get the group-0 key explicitly. */
async function deriveKey(
  h: ReturnType<typeof createHarness>,
  session: string,
  walletId: string,
  groupIndex = 0,
): Promise<string> {
  const res = ok(await h.call("nostr.deriveKey", { walletId, groupIndex }, session));
  return strField(res, "publicKey");
}

describe("create / import", () => {
  it("creates a passkey wallet matching the vector and opens a session", async () => {
    const h = createHarness();
    await h.settle();
    expect(field(ok(await h.call("status")), "vault")).toBe("uninitialized");

    const { session, walletId } = await createPasskeyWallet(h);
    expect(session).toMatch(/^[0-9a-f]{32}$/);
    expect(walletId).toBe(passkeyVector.vector.walletId);
    const publicKey = await deriveKey(h, session, walletId);
    expect(publicKey).toBe(passkeyVector.vector.publicKey);
    expect(npubEncode(publicKey)).toMatch(/^npub1/);

    const status = lastStatus(h);
    expect(status.vault).toBe("unlocked");
    expect(status.wallets[0]?.walletId).toBe(passkeyVector.vector.walletId);
    expect(status.wallets[0]?.backedUp).toBe(true);
    expect(status.nostr.keys[0]?.publicKey).toBe(publicKey);
    expect(status.factors).toHaveLength(1);
  });

  it("rejects a duplicate restore with already-exists", async () => {
    const h = createHarness();
    await h.settle();
    const { session } = await createPasskeyWallet(h);
    expect(
      errCode(
        await h.call(
          "wallet.restoreWithPasskey",
          { credentialId: CREDENTIAL_ID, prfWallet: new Uint8Array(PRF_WALLET) },
          session,
        ),
      ),
    ).toBe("already-exists");
  });

  it("imports a NIP-06 mnemonic wallet and derives group-0 key", async () => {
    const h = createHarness();
    await h.settle();
    const res = ok(
      await h.call("wallet.importMnemonic", {
        mnemonic: utf8ToBytes(nip06.vectors[0]!.mnemonic),
        factor: { kind: "passkey", credentialId: CREDENTIAL_ID, prf: new Uint8Array(PRF_VAULT) },
      }),
    );
    const session = strField(res, "session");
    const walletId = strField(field(res, "wallet"), "walletId");
    const publicKey = await deriveKey(h, session, walletId);
    expect(publicKey).toBe(nip06.vectors[0]!.publicKey);
  });

  it("imports nsec and ncryptsec keys", async () => {
    const h = createHarness();
    await h.settle();
    const { session } = await createPasskeyWallet(h);
    const imported = ok(
      await h.call(
        "nostr.importKey",
        { input: { kind: "nsec", nsec: utf8ToBytes(nip06.vectors[0]!.nsec) } },
        session,
      ),
    );
    expect(strField(field(imported, "key"), "publicKey")).toBe(nip06.vectors[0]!.publicKey);

    // NIP-49 spec vector: password "nostr", logN 16.
    const ncryptsec =
      "ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p";
    const imported2 = ok(
      await h.call(
        "nostr.importKey",
        { input: { kind: "ncryptsec", ncryptsec, password: utf8ToBytes("nostr") } },
        session,
      ),
    );
    const pk = strField(field(imported2, "key"), "publicKey");
    const sk = hexToBytes("3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683");
    expect(pk).toBe(Keys.fromSecretKey(sk).publicKey);
  });
});

describe("mnemonic draft", () => {
  it("keeps the draft on wrong answers and completes on right answers", async () => {
    const h = createHarness();
    await h.settle();
    const created = ok(
      await h.call("wallet.createMnemonic", {
        words: 12,
        factor: { kind: "password", password: new Uint8Array(PASSWORD) },
      }),
    );
    const draft = strField(created, "draft");
    const quiz = intList(created, "quiz");
    const words = new TextDecoder().decode(bytesField(created, "words")).split(" ");
    expect(quiz).toHaveLength(3);
    expect(new Set(quiz).size).toBe(3);

    const wrong = quiz.map(() => utf8ToBytes("abandon"));
    expect(errCode(await h.call("wallet.confirmMnemonic", { draft, answers: wrong }))).toBe(
      "invalid-input",
    );

    const right = quiz.map((p) => utf8ToBytes(words[p]!));
    const res = ok(await h.call("wallet.confirmMnemonic", { draft, answers: right }));
    expect(strField(res, "session")).toMatch(/^[0-9a-f]{32}$/);
    expect(lastStatus(h).vault).toBe("unlocked");
    expect(lastStatus(h).wallets[0]?.backedUp).toBe(true);
  });

  it("discards the draft", async () => {
    const h = createHarness();
    await h.settle();
    const created = ok(
      await h.call("wallet.createMnemonic", {
        words: 12,
        factor: { kind: "password", password: new Uint8Array(PASSWORD) },
      }),
    );
    const draft = strField(created, "draft");
    expect(ok(await h.call("wallet.discardMnemonic", { draft }))).toBeNull();
    expect(
      errCode(
        await h.call("wallet.confirmMnemonic", {
          draft,
          answers: [utf8ToBytes("a"), utf8ToBytes("b"), utf8ToBytes("c")],
        }),
      ),
    ).toBe("not-found");
  });
});

describe("nostr operations", () => {
  it("derives keys, discovers pubkeys, and rejects duplicate derivation", async () => {
    const h = createHarness();
    await h.settle();
    const { session, walletId } = await createPasskeyWallet(h);
    const pk0 = await deriveKey(h, session, walletId);

    const discovered = listField(
      ok(await h.call("nostr.discover", { walletId, from: 0, count: 3 }, session)),
      "keys",
    );
    expect(discovered).toHaveLength(3);
    expect(strField(must(discovered[0]), "publicKey")).toBe(pk0);
    expect(numField(must(discovered[1]), "groupIndex")).toBe(1);

    const derived = ok(await h.call("nostr.deriveKey", { walletId, groupIndex: 1 }, session));
    expect(strField(derived, "publicKey")).toBe(strField(must(discovered[1]), "publicKey"));
    expect(errCode(await h.call("nostr.deriveKey", { walletId, groupIndex: 1 }, session))).toBe(
      "already-exists",
    );
    expect(
      errCode(
        await h.call("nostr.deriveKey", { walletId: "0000000000000000", groupIndex: 0 }, session),
      ),
    ).toBe("not-found");
  });

  it("signs events that verify", async () => {
    const h = createHarness();
    await h.settle();
    const { session, walletId } = await createPasskeyWallet(h);
    const publicKey = await deriveKey(h, session, walletId);
    const event = ok(
      await h.call(
        "nostr.signEvent",
        {
          publicKey,
          event: { kind: 1, created_at: 1_700_000_001, tags: [], content: "gm" },
        },
        session,
      ),
    ) as unknown as Event;
    expect(verifyEvent(event)).toBe(true);
    expect(event.pubkey).toBe(publicKey);
  });

  it("round-trips nip04 and nip44 between two keys", async () => {
    const h = createHarness();
    await h.settle();
    const { session, walletId } = await createPasskeyWallet(h);
    const alice = await deriveKey(h, session, walletId);
    const bob = strField(
      field(ok(await h.call("nostr.generateKey", {}, session)), "key"),
      "publicKey",
    );
    const c44 = ok(
      await h.call("nostr.nip44Encrypt", { publicKey: alice, peer: bob, text: "hello" }, session),
    );
    const p44 = ok(
      await h.call(
        "nostr.nip44Decrypt",
        { publicKey: bob, peer: alice, text: c44 as string },
        session,
      ),
    );
    expect(p44).toBe("hello");

    const c04 = ok(
      await h.call("nostr.nip04Encrypt", { publicKey: alice, peer: bob, text: "hi" }, session),
    );
    const p04 = ok(
      await h.call(
        "nostr.nip04Decrypt",
        { publicKey: bob, peer: alice, text: c04 as string },
        session,
      ),
    );
    expect(p04).toBe("hi");
  });

  it("unwraps gift wraps and isolates corrupted items", async () => {
    const h = createHarness();
    await h.settle();
    const { session, walletId } = await createPasskeyWallet(h);
    const publicKey = await deriveKey(h, session, walletId);

    const sender = new KeysSigner(Keys.generate());
    const rumor = createRumor(await sender.getPublicKey(), { kind: 14, content: "secret dm" });
    const wrapped = await nip59Wrap(sender, publicKey, rumor);
    const res = listField(
      ok(
        await h.call(
          "nostr.unwrapGiftWraps",
          { publicKey, events: [wrapped, { ...wrapped, content: "broken" }] },
          session,
        ),
      ),
      "results",
    );
    expect(res).toHaveLength(2);
    const [first, second] = res;
    expect(first).toHaveProperty("ok");
    expect(second).toHaveProperty("err");
  });

  it("creates a nip46-client key and removes it without verification", async () => {
    const h = createHarness();
    await h.settle();
    const { session } = await createPasskeyWallet(h);
    const key = strField(
      ok(await h.call("nostr.createNip46ClientKey", null, session)),
      "publicKey",
    );
    expect(ok(await h.call("nostr.removeKey", { publicKey: key }, session))).toBeNull();

    const generated = strField(
      field(ok(await h.call("nostr.generateKey", {}, session)), "key"),
      "publicKey",
    );
    expect(errCode(await h.call("nostr.removeKey", { publicKey: generated }, session))).toBe(
      "invalid-input",
    );
    expect(
      ok(
        await h.call(
          "nostr.removeKey",
          {
            publicKey: generated,
            verify: {
              kind: "passkey",
              credentialId: CREDENTIAL_ID,
              prf: new Uint8Array(PRF_VAULT),
            },
          },
          session,
        ),
      ),
    ).toBeNull();
  });
});

describe("exports and data keys", () => {
  it("exports the mnemonic and nostr keys", async () => {
    const h = createHarness();
    await h.settle();
    const { session, walletId } = await createPasskeyWallet(h);
    const publicKey = await deriveKey(h, session, walletId);
    const verify = {
      kind: "passkey",
      credentialId: CREDENTIAL_ID,
      prf: new Uint8Array(PRF_VAULT),
    };

    const exported = ok(await h.call("wallet.exportMnemonic", { verify, walletId }, session));
    expect(new TextDecoder().decode(exported as Uint8Array)).toBe(passkeyVector.vector.mnemonic);

    const nsecBytes = ok(
      await h.call(
        "nostr.exportKey",
        {
          verify: { kind: "passkey", credentialId: CREDENTIAL_ID, prf: new Uint8Array(PRF_VAULT) },
          publicKey,
          format: { kind: "nsec" },
        },
        session,
      ),
    );
    const decoded = nip19Decode(new TextDecoder().decode(nsecBytes as Uint8Array));
    expect(decoded.type).toBe("nsec");
    expect(bytesToHex(nsecData(decoded))).toBe(passkeyVector.vector.privateKey);

    const ncryptBytes = ok(
      await h.call(
        "nostr.exportKey",
        {
          verify: { kind: "passkey", credentialId: CREDENTIAL_ID, prf: new Uint8Array(PRF_VAULT) },
          publicKey,
          format: { kind: "ncryptsec", password: utf8ToBytes("exportpw1234") },
        },
        session,
      ),
    );
    const sk = await nip49Decrypt(
      new TextDecoder().decode(ncryptBytes as Uint8Array),
      "exportpw1234",
      { maxLogN: 20 },
    );
    expect(Keys.fromSecretKey(sk).publicKey).toBe(publicKey);
  });

  it("data keys are stable across lock/unlock", async () => {
    const h = createHarness();
    await h.settle();
    const { session } = await createPasskeyWallet(h);
    const first = ok(await h.call("dataKeys.get", { purpose: "meowl-db" }, session));
    expect(first).toBeInstanceOf(Uint8Array);
    expect(first as Uint8Array).toHaveLength(32);
    const again = ok(await h.call("dataKeys.get", { purpose: "meowl-db" }, session));
    expect(bytesToHex(again as Uint8Array)).toBe(bytesToHex(first as Uint8Array));

    // Lock = the host killed the worker; a fresh kernel over the same store is the respawn.
    const h2 = respawn(h);
    await h2.settle();
    const unlocked = ok(
      await h2.call("vault.unlock", {
        factor: { kind: "passkey", credentialId: CREDENTIAL_ID, prf: new Uint8Array(PRF_VAULT) },
      }),
    );
    const session2 = strField(unlocked, "session");
    const afterLock = ok(await h2.call("dataKeys.get", { purpose: "meowl-db" }, session2));
    expect(bytesToHex(afterLock as Uint8Array)).toBe(bytesToHex(first as Uint8Array));
  });
});

describe("factors, lock, reset", () => {
  it("adds and removes a password factor; cannot remove the last", async () => {
    const h = createHarness();
    await h.settle();
    const { session } = await createPasskeyWallet(h);
    const verify = { kind: "passkey", credentialId: CREDENTIAL_ID, prf: new Uint8Array(PRF_VAULT) };
    const added = ok(
      await h.call(
        "vault.addFactor",
        { verify, factor: { kind: "password", password: new Uint8Array(PASSWORD) } },
        session,
      ),
    );
    const addedId = strField(added, "id");
    expect(strField(added, "kind")).toBe("password");
    expect(lastStatus(h).factors).toHaveLength(2);

    // The new password factor can unlock after a lock — a fresh kernel over the same store.
    const h2 = respawn(h);
    await h2.settle();
    const unlocked = ok(
      await h2.call("vault.unlock", {
        factor: { kind: "password", password: new Uint8Array(PASSWORD) },
      }),
    );
    const session2 = strField(unlocked, "session");
    expect(lastStatus(h2).vault).toBe("unlocked");

    // Removing with password verify works; the last factor cannot be removed.
    expect(
      ok(
        await h2.call(
          "vault.removeFactor",
          { verify: { kind: "password", password: new Uint8Array(PASSWORD) }, id: addedId },
          session2,
        ),
      ),
    ).toBeNull();
    const lastId = factorId(lastStatus(h2).factors[0]);
    expect(
      errCode(
        await h2.call(
          "vault.removeFactor",
          {
            verify: {
              kind: "passkey",
              credentialId: CREDENTIAL_ID,
              prf: new Uint8Array(PRF_VAULT),
            },
            id: lastId,
          },
          session2,
        ),
      ),
    ).toBe("invalid-input");
  });

  it("changes the password: addFactor replaces the single password factor atomically", async () => {
    const h = createHarness();
    await h.settle();
    const { session } = await createPasskeyWallet(h);
    const verify = { kind: "passkey", credentialId: CREDENTIAL_ID, prf: new Uint8Array(PRF_VAULT) };
    ok(
      await h.call(
        "vault.addFactor",
        {
          verify,
          factor: { kind: "password", password: utf8ToBytes("first correct horse") },
        },
        session,
      ),
    );
    // Change password: verify with the old password, add a new password factor.
    const changed = ok(
      await h.call(
        "vault.addFactor",
        {
          verify: { kind: "password", password: utf8ToBytes("first correct horse") },
          factor: { kind: "password", password: utf8ToBytes("second battery staple") },
        },
        session,
      ),
    );
    const passwordFactors = lastStatus(h).factors.filter((f) => f.kind === "password");
    expect(passwordFactors).toHaveLength(1);
    expect(factorId(passwordFactors[0])).toBe(strField(changed, "id"));

    const h2 = respawn(h);
    await h2.settle();
    // The old password is a normal wrong-password failure; the new one opens the vault.
    expect(
      errCode(
        await h2.call("vault.unlock", {
          factor: { kind: "password", password: utf8ToBytes("first correct horse") },
        }),
      ),
    ).toBe("wrong-password");
    const unlocked = ok(
      await h2.call("vault.unlock", {
        factor: { kind: "password", password: utf8ToBytes("second battery staple") },
      }),
    );
    expect(strField(unlocked, "session")).toBeTypeOf("string");
  });

  it("keeps at least one factor while replacing the password factor", async () => {
    const h = createHarness();
    await h.settle();
    // A password-only vault: the single factor is a password.
    const created = ok(
      await h.call("wallet.createMnemonic", {
        words: 12,
        factor: { kind: "password", password: utf8ToBytes("only factor password") },
      }),
    );
    const draft = strField(created, "draft");
    const words = new TextDecoder().decode(bytesField(created, "words")).split(" ");
    const quiz = intList(created, "quiz");
    const answers = quiz.map((i) => utf8ToBytes(must(words[i])));
    const confirmed = ok(await h.call("wallet.confirmMnemonic", { draft, answers }));
    const session = strField(confirmed, "session");
    expect(lastStatus(h).factors).toHaveLength(1);

    // Replacing the only factor in one commit never drops below one.
    ok(
      await h.call(
        "vault.addFactor",
        {
          verify: { kind: "password", password: utf8ToBytes("only factor password") },
          factor: { kind: "password", password: utf8ToBytes("rotated factor pass") },
        },
        session,
      ),
    );
    expect(lastStatus(h).factors).toHaveLength(1);
  });

  it("resets to uninitialized even when the store watch never fires", async () => {
    // A host store that suppresses change notices for the kernel's own commits (as the real
    // Web/Node stores do): the commit path itself must reload the image and drop the session.
    const h = createHarness({ wrapStore: nonEchoing });
    await h.settle();
    const { session } = await createPasskeyWallet(h);
    expect(ok(await h.call("vault.reset", null, session))).toBeNull();
    expect(lastStatus(h).vault).toBe("uninitialized");
    expect(lockReasons(h.events)).toContain("user");
  });

  it("locks via the injected idle timer with no request in flight", async () => {
    const h = createHarness({ idleMs: 60_000 });
    await h.settle();
    const { session } = await createPasskeyWallet(h);
    h.advance(61_000);
    await h.settle();
    expect(lastStatus(h).vault).toBe("locked");
    expect(lockReasons(h.events)).toContain("idle");
    expect(errCode(await h.call("nostr.createNip46ClientKey", null, session))).toBe("locked");
  });

  it("a respawned kernel starts locked and rejects a stale session id", async () => {
    const h = createHarness();
    await h.settle();
    const { session } = await createPasskeyWallet(h);
    // Lock is host-side now: the worker is terminated and a fresh kernel respawns on the store.
    const h2 = respawn(h);
    await h2.settle();
    expect(lastStatus(h2).vault).toBe("locked");
    expect(errCode(await h2.call("nostr.createNip46ClientKey", null, session))).toBe("locked");
    // A stale session id is rejected even after re-unlock.
    const unlocked = ok(
      await h2.call("vault.unlock", {
        factor: { kind: "passkey", credentialId: CREDENTIAL_ID, prf: new Uint8Array(PRF_VAULT) },
      }),
    );
    expect(strField(unlocked, "session")).not.toBe(session);
  });

  it("resets back to uninitialized", async () => {
    const h = createHarness();
    await h.settle();
    const { session } = await createPasskeyWallet(h);
    expect(ok(await h.call("vault.reset", null, session))).toBeNull();
    await h.settle();
    expect(field(ok(await h.call("status")), "vault")).toBe("uninitialized");
  });

  it("deletes a wallet and its derived keys atomically", async () => {
    const h = createHarness();
    await h.settle();
    const { session, walletId } = await createPasskeyWallet(h);
    const derivedPk = await deriveKey(h, session, walletId, 0);
    ok(await h.call("nostr.deriveKey", { walletId, groupIndex: 5 }, session));
    // A standalone key is not the wallet's: it survives the deletion.
    const standalone = strField(
      field(ok(await h.call("nostr.generateKey", {}, session)), "key"),
      "publicKey",
    );
    expect(lastStatus(h).nostr.keys).toHaveLength(3);
    expect(
      ok(
        await h.call(
          "wallet.delete",
          {
            verify: {
              kind: "passkey",
              credentialId: CREDENTIAL_ID,
              prf: new Uint8Array(PRF_VAULT),
            },
            walletId,
          },
          session,
        ),
      ),
    ).toBeNull();
    const status = lastStatus(h);
    expect(status.wallets).toHaveLength(0);
    expect(status.nostr.keys.map((k) => k.publicKey)).toStrictEqual([standalone]);
    // The delete committed atomically: no derived row survived, no signer is left in the pool.
    expect(errCode(await h.call("nostr.deriveKey", { walletId, groupIndex: 6 }, session))).toBe(
      "not-found",
    );
    expect(
      errCode(
        await h.call(
          "nostr.signEvent",
          {
            publicKey: derivedPk,
            event: { kind: 1, created_at: 1, tags: [], content: "x" },
          },
          session,
        ),
      ),
    ).toBe("not-found");
  });
});

describe("session expiry and rate limiting", () => {
  it("locks on idle expiry", async () => {
    const h = createHarness({ idleMs: 60_000 });
    await h.settle();
    const { session } = await createPasskeyWallet(h);
    h.advance(61_000);
    expect(errCode(await h.call("nostr.createNip46ClientKey", null, session))).toBe("locked");
    expect(lockReasons(h.events)).toContain("idle");
  });

  it("locks on max-session expiry", async () => {
    const h = createHarness({ maxSessionMs: 3_600_000, idleMs: 10 * 3_600_000 });
    await h.settle();
    const { session } = await createPasskeyWallet(h);
    h.advance(3_700_000);
    // status does not need a session; the vault field now reports locked.
    expect(field(ok(await h.call("status")), "vault")).toBe("locked");
    expect(errCode(await h.call("nostr.createNip46ClientKey", null, session))).toBe("locked");
    expect(lockReasons(h.events)).toContain("expired");
  });

  it("a backward wall-clock jump never extends the session", async () => {
    const h = createHarness({ idleMs: 60_000 });
    await h.settle();
    const { session } = await createPasskeyWallet(h);
    // The wall clock jumps an hour backwards: session deadlines ride the monotonic clock.
    h.advanceWall(-3_600_000);
    h.advance(61_000);
    await h.settle();
    expect(lastStatus(h).vault).toBe("locked");
    expect(lockReasons(h.events)).toContain("idle");
    expect(errCode(await h.call("nostr.createNip46ClientKey", null, session))).toBe("locked");
  });

  it("a forward wall-clock jump never shortens the session", async () => {
    const h = createHarness({ idleMs: 60_000 });
    await h.settle();
    const { session } = await createPasskeyWallet(h);
    h.advanceWall(10 * 3_600_000); // the wall clock leaps forward ten hours
    // Elapsed time is what counts: still unlocked a second later, idle-locked at 60 s.
    h.advance(1000);
    expect("ok" in (await h.call("nostr.createNip46ClientKey", null, session))).toBe(true);
    h.advance(61_000);
    await h.settle();
    expect(lastStatus(h).vault).toBe("locked");
    expect(lockReasons(h.events)).toContain("idle");
  });
});

describe("password rate limiting", () => {
  /** A vault whose only factor is a password, created on `h`. */
  async function createPasswordVault(h: Harness): Promise<void> {
    ok(
      await h.call("wallet.importMnemonic", {
        mnemonic: utf8ToBytes(nip06.vectors[0]!.mnemonic),
        factor: { kind: "password", password: new Uint8Array(PASSWORD) },
      }),
    );
  }

  const badPassword = async (h: Harness) =>
    h.call("vault.unlock", {
      factor: { kind: "password", password: utf8ToBytes("a wrong password") },
    });

  it("limits wrong passwords: 30s, 60s, 300s — on a non-echoing store", async () => {
    // The real Web/Node stores never echo a worker's own commits (issue #91).
    const h = createHarness({ wrapStore: nonEchoing });
    await h.settle();
    await createPasswordVault(h);
    const h2 = respawn(h, nonEchoing);
    await h2.settle();

    // Failures 1-4: wrong-password, no rate limit yet.
    for (let i = 0; i < 4; i++) {
      // oxlint-disable-next-line eslint/no-await-in-loop -- unlock attempts are sequential by design
      expect(errCode(await badPassword(h2))).toBe("wrong-password");
    }
    // The 5th failure arms the 30 s backoff.
    expect(errCode(await badPassword(h2))).toBe("wrong-password");
    const t = h2.wallNow();
    await expect(storedFailedAttempts(h.store)).resolves.toBe(5);
    // The 6th attempt is rate-limited with the armed deadline — never counted: retries cannot
    // push the horizon forward.
    const limited = await badPassword(h2);
    expect(errCode(limited)).toBe("rate-limited");
    expect(errPayload(limited).retryAt).toBe(t + 30_000);
    await expect(storedFailedAttempts(h.store)).resolves.toBe(5);
    // The next real failure lands the 6th increment and arms the 60 s tier.
    h2.advanceWall(61_000);
    expect(errCode(await badPassword(h2))).toBe("wrong-password");
    const limited2 = await badPassword(h2);
    expect(errCode(limited2)).toBe("rate-limited");
    expect(errPayload(limited2).retryAt).toBe(t + 61_000 + 60_000);
    // The 7th real failure arms the 300 s tier.
    h2.advanceWall(61_000);
    expect(errCode(await badPassword(h2))).toBe("wrong-password");
    const limited3 = await badPassword(h2);
    expect(errCode(limited3)).toBe("rate-limited");
    expect(errPayload(limited3).retryAt).toBe(t + 122_000 + 300_000);
    // Success resets the counter — a fresh failure starts at 1.
    h2.advanceWall(301_000);
    const unlocked = await h2.call("vault.unlock", {
      factor: { kind: "password", password: new Uint8Array(PASSWORD) },
    });
    expect("ok" in unlocked).toBe(true);
    await expect(storedFailedAttempts(h.store)).resolves.toBe(0);
    const h3 = respawn(h, nonEchoing);
    await h3.settle();
    expect(errCode(await badPassword(h3))).toBe("wrong-password");
    await expect(storedFailedAttempts(h.store)).resolves.toBe(1);
  });

  it("pipelined attempts never lose an increment", async () => {
    const h = createHarness({ wrapStore: nonEchoing });
    await h.settle();
    await createPasswordVault(h);
    const h2 = respawn(h, nonEchoing);
    await h2.settle();
    const results = await Promise.all(Array.from({ length: 6 }, async () => badPassword(h2)));
    const codes = results.map(errCode);
    expect(codes.filter((c) => c === "wrong-password")).toHaveLength(5);
    expect(codes.filter((c) => c === "rate-limited")).toHaveLength(1);
    await expect(storedFailedAttempts(h.store)).resolves.toBe(5);
  });

  it("retries during backoff move neither the counter nor the deadline", async () => {
    const h = createHarness({ wrapStore: nonEchoing });
    await h.settle();
    await createPasswordVault(h);
    const h2 = respawn(h, nonEchoing);
    await h2.settle();
    for (let i = 0; i < 5; i++) {
      // oxlint-disable-next-line eslint/no-await-in-loop -- unlock attempts are sequential by design
      expect(errCode(await badPassword(h2))).toBe("wrong-password");
    }
    const t = h2.wallNow();
    // Every further attempt while armed reports the same deadline and leaves the counter at 5.
    for (let i = 0; i < 4; i++) {
      // oxlint-disable-next-line eslint/no-await-in-loop -- unlock attempts are sequential by design
      const limited = await badPassword(h2);
      expect(errCode(limited)).toBe("rate-limited");
      expect(errPayload(limited).retryAt).toBe(t + 30_000);
    }
    await expect(storedFailedAttempts(h.store)).resolves.toBe(5);
  });

  it("two kernels sharing one store never lose an increment", async () => {
    const h = createHarness({ wrapStore: nonEchoing });
    await h.settle();
    await createPasswordVault(h);
    const a = respawn(h, nonEchoing);
    const b = respawn(h, nonEchoing);
    await a.settle();
    await b.settle();
    const results = await Promise.all([
      ...Array.from({ length: 5 }, async () => badPassword(a)),
      ...Array.from({ length: 5 }, async () => badPassword(b)),
    ]);
    // The wrong-password/rate-limited split depends on interleaving — whichever attempts reload
    // before the counter crosses 5 see an unarmed backoff. What must hold: every attempt either
    // failed honestly or was limited, every honest miss landed its increment (never lost), and
    // enough attempts ran far enough to arm the backoff.
    const codes = results.map(errCode);
    for (const code of codes) {
      expect(["wrong-password", "rate-limited"]).toContain(code);
    }
    const counted = codes.filter((c) => c === "wrong-password").length;
    await expect(storedFailedAttempts(h.store)).resolves.toBe(counted);
    expect(counted).toBeGreaterThanOrEqual(5);
  });

  it("a password attempt on a passkey-only vault is invalid-input and never counted", async () => {
    const h = createHarness({ wrapStore: nonEchoing });
    await h.settle();
    await createPasskeyWallet(h);
    const h2 = respawn(h, nonEchoing);
    await h2.settle();
    expect(errCode(await badPassword(h2))).toBe("invalid-input");
    await expect(storedFailedAttempts(h.store)).resolves.toBe(0);
  });

  it("a passkey unlock is never gated by password backoff", async () => {
    const h = createHarness({ wrapStore: nonEchoing });
    await h.settle();
    const { session } = await createPasskeyWallet(h);
    ok(
      await h.call(
        "vault.addFactor",
        {
          verify: passkeyFactor(),
          factor: { kind: "password", password: new Uint8Array(PASSWORD) },
        },
        session,
      ),
    );
    const h2 = respawn(h, nonEchoing);
    await h2.settle();
    // Arm the backoff fully — the sixth attempt is rejected without counting.
    for (let i = 0; i < 6; i++) {
      // oxlint-disable-next-line eslint/no-await-in-loop -- sequential attempts
      await badPassword(h2);
    }
    await expect(storedFailedAttempts(h.store)).resolves.toBe(5);
    // The passkey path does not consult the password counters at all.
    const unlocked = await h2.call("vault.unlock", { factor: passkeyFactor() });
    expect("ok" in unlocked).toBe(true);
  });
});

describe("integrity", () => {
  it("a record that fails authentication at unlock corrupts the vault; reset recovers", async () => {
    const h = createHarness();
    await h.settle();
    await createPasskeyWallet(h);
    const image = await h.store.load();
    const record = must(image.records.find((r) => r.kind === "entropy"));
    const header = JSON.parse(record.header) as Record<string, unknown>;
    header["backedUp"] = false;
    await h.store.commit([
      { op: "put-record", record: { ...record, header: JSON.stringify(header) } },
    ]);
    await h.settle();
    const res = await h.call("vault.unlock", {
      factor: { kind: "passkey", credentialId: CREDENTIAL_ID, prf: new Uint8Array(PRF_VAULT) },
    });
    expect(errCode(res)).toBe("integrity");
    // The DEK opened but a record failed authentication: the vault is corrupted.
    expect(lastStatus(h).vault).toBe("corrupted");
    // While corrupted only status and vault.reset are served — no session opens.
    expect(errCode(await h.call("nostr.generateKey", {}))).toBe("integrity");
    expect(
      errCode(
        await h.call("vault.unlock", {
          factor: { kind: "passkey", credentialId: CREDENTIAL_ID, prf: new Uint8Array(PRF_VAULT) },
        }),
      ),
    ).toBe("integrity");
    expect(ok(await h.call("vault.reset"))).toBeNull();
    expect(lastStatus(h).vault).toBe("uninitialized");
    // The corruption latch is gone: an empty vault fails unlock honestly.
    expect(
      errCode(
        await h.call("vault.unlock", {
          factor: { kind: "password", password: new Uint8Array(PASSWORD) },
        }),
      ),
    ).toBe("invalid-input");
  });

  it("rejects swapped sealed blobs between records", async () => {
    const h = createHarness();
    await h.settle();
    const { session, walletId } = await createPasskeyWallet(h);
    await deriveKey(h, session, walletId); // a second sealed record to swap with
    const image = await h.store.load();
    const [rawA, rawB] = image.records;
    const a = must(rawA);
    const b = must(rawB);
    await h.store.commit([
      { op: "put-record", record: { ...a, sealed: b.sealed } },
      { op: "put-record", record: { ...b, sealed: a.sealed } },
    ]);
    await h.settle();
    const res = await h.call("vault.unlock", {
      factor: { kind: "passkey", credentialId: CREDENTIAL_ID, prf: new Uint8Array(PRF_VAULT) },
    });
    expect(errCode(res)).toBe("integrity");
    expect(lastStatus(h).vault).toBe("corrupted");
  });

  it("a public header that fails to parse corrupts the vault on reload", async () => {
    const h = createHarness();
    await h.settle();
    await createPasskeyWallet(h);
    const image = await h.store.load();
    const factor = must(image.factors[0]);
    await h.store.commit([{ op: "put-factor", factor: { ...factor, header: "not json" } }]);
    await h.settle();
    // The watch reload parsed the tampered header: corrupted, and the bad row is omitted.
    const status = lastStatus(h);
    expect(status.vault).toBe("corrupted");
    expect(status.factors).toHaveLength(0);
    expect(status.wallets).toHaveLength(1);
    expect(
      errCode(
        await h.call("vault.unlock", {
          factor: { kind: "password", password: new Uint8Array(PASSWORD) },
        }),
      ),
    ).toBe("integrity");
    expect(ok(await h.call("vault.reset"))).toBeNull();
    expect(lastStatus(h).vault).toBe("uninitialized");
  });

  it("a stored record of an unknown kind is unsupported — the vault locks and stays untouched", async () => {
    const h = createHarness();
    await h.settle();
    const { session } = await createPasskeyWallet(h);
    const before = await h.store.load();
    // Simulate a vault written by a newer build: a record kind this kernel does not own.
    await h.store.commit([
      {
        op: "put-record",
        record: {
          kind: "spark-key",
          id: "00".repeat(32),
          header: JSON.stringify({ publicKey: "00".repeat(32), createdAt: 0 }),
          sealed: new Uint8Array(48),
        },
      },
    ]);
    await h.settle();
    const status = lastStatus(h);
    expect(status.vault).toBe("unsupported");
    // The unlocked session is invalidated immediately, not at the next timeout.
    expect(lockReasons(h.events)).toContain("invalidated");
    // Everything except status and vault.reset fails closed — the store bytes stay as written.
    expect(
      errCode(
        await h.call("vault.unlock", {
          factor: { kind: "passkey", credentialId: CREDENTIAL_ID, prf: new Uint8Array(PRF_VAULT) },
        }),
      ),
    ).toBe("unsupported");
    expect(errCode(await h.call("nostr.createNip46ClientKey", null, session))).toBe("unsupported");
    const untouched = await h.store.load();
    expect(untouched.records).toHaveLength(before.records.length + 1);
    expect(untouched.records.some((r) => r.kind === "spark-key")).toBe(true);
    expect(ok(await h.call("vault.reset"))).toBeNull();
    expect(lastStatus(h).vault).toBe("uninitialized");
  });

  it("a racing establish fails with conflict and writes nothing", async () => {
    const h = createHarness();
    await h.settle();
    const created = ok(
      await h.call("wallet.createMnemonic", {
        words: 12,
        factor: { kind: "password", password: new Uint8Array(PASSWORD) },
      }),
    );
    const draft = strField(created, "draft");
    const quiz = intList(created, "quiz");
    const words = new TextDecoder().decode(bytesField(created, "words")).split(" ");

    // Another tab establishes a vault first.
    await h.store.commit([{ op: "init", meta: metaOf() }]);
    await h.settle();

    const answers = quiz.map((p) => utf8ToBytes(words[p]!));
    const res = await h.call("wallet.confirmMnemonic", { draft, answers });
    expect(errCode(res)).toBe("conflict");
    const image = await h.store.load();
    expect(image.records).toHaveLength(0);
    expect(image.factors).toHaveLength(0);
  });

  it("rejects malformed requests with integrity and keeps serving", async () => {
    const h = createHarness();
    await h.settle();
    expect(errCode(await h.call("no.such.method"))).toBe("integrity");
    expect(errCode(await h.call("status", { unexpected: 1 }))).toBe("integrity");
    expect(field(ok(await h.call("status")), "protocol")).toBe(1);
  });

  it("a store that fails to load reports corrupted until reset re-establishes it", async () => {
    let broken = true;
    const h = createHarness({
      wrapStore: (store) => ({ ...store, load: failingLoad(store, () => broken) }),
    });
    await h.settle();
    // The enclave did not crash: the startup status event still went out, reporting corrupted.
    expect(h.events.some((e) => e.event === "status")).toBe(true);
    expect(lastStatus(h).vault).toBe("corrupted");
    // Every request except status and vault.reset answers integrity.
    expect(
      errCode(
        await h.call("vault.unlock", {
          factor: { kind: "password", password: new Uint8Array(PASSWORD) },
        }),
      ),
    ).toBe("integrity");
    expect(errCode(await h.call("nostr.generateKey", {}))).toBe("integrity");
    expect(field(ok(await h.call("status")), "vault")).toBe("corrupted");
    // vault.reset is the recovery path: its commit re-establishes the store.
    broken = false;
    await h.call("vault.reset");
    expect(lastStatus(h).vault).toBe("uninitialized");
    // Back to honest behavior: unlock on an empty vault is invalid-input, not integrity.
    expect(
      errCode(
        await h.call("vault.unlock", {
          factor: { kind: "password", password: new Uint8Array(PASSWORD) },
        }),
      ),
    ).toBe("invalid-input");
  });
});

describe("vault health", () => {
  it("a meta format this build cannot read is unsupported and stays untouched", async () => {
    const h = createHarness();
    await h.settle();
    // A newer build initialized this vault.
    await h.store.commit([{ op: "init", meta: metaOf({ format: 3 }) }]);
    await h.settle();
    expect(lastStatus(h).vault).toBe("unsupported");
    expect(errCode(await h.call("vault.unlock", { factor: passkeyFactor() }))).toBe("unsupported");
    // Nothing is rewritten and reset still recovers.
    const metaAfter = await storedMeta(h.store);
    expect(metaAfter.format).toBe(3);
    expect(ok(await h.call("vault.reset"))).toBeNull();
    expect(lastStatus(h).vault).toBe("uninitialized");
  });

  it("a factor kind this build does not know is unsupported", async () => {
    const h = createHarness();
    await h.settle();
    await h.store.commit([
      { op: "init", meta: metaOf() },
      {
        op: "put-factor",
        factor: {
          kind: "u2f-key",
          id: "cc".repeat(16),
          header: "{}",
          sealed: new Uint8Array(48),
        },
      },
    ]);
    await h.settle();
    expect(lastStatus(h).vault).toBe("unsupported");
    expect(errCode(await h.call("vault.unlock", { factor: passkeyFactor() }))).toBe("unsupported");
  });

  it("a password factor with unknown KDF parameters is unsupported", async () => {
    const h = createHarness();
    await h.settle();
    await h.store.commit([
      { op: "init", meta: metaOf() },
      {
        op: "put-factor",
        factor: {
          kind: "password",
          id: "dd".repeat(16),
          header: JSON.stringify({
            salt: "AAAAAAAAAAAAAAAAAAAAAA",
            iterations: 1_000_000,
            createdAt: 0,
          }),
          sealed: new Uint8Array(48),
        },
      },
    ]);
    await h.settle();
    expect(lastStatus(h).vault).toBe("unsupported");
    const stored = await h.store.load();
    expect(stored.factors[0]?.kind).toBe("password");
  });

  it("a malformed header of a known kind while unlocked is corrupted and locks at once", async () => {
    const h = createHarness();
    await h.settle();
    const { session } = await createPasskeyWallet(h);
    await h.store.commit([
      {
        op: "put-factor",
        factor: {
          kind: "password",
          id: "ee".repeat(16),
          header: "not json",
          sealed: new Uint8Array(48),
        },
      },
    ]);
    await h.settle();
    expect(lastStatus(h).vault).toBe("corrupted");
    // The unlocked session is invalidated immediately — DEK and drafts are wiped.
    expect(lockReasons(h.events)).toContain("invalidated");
    expect(errCode(await h.call("nostr.createNip46ClientKey", null, session))).toBe("integrity");
    expect(ok(await h.call("vault.reset"))).toBeNull();
    expect(lastStatus(h).vault).toBe("uninitialized");
  });

  it("a transient load failure is unavailable — retried, never latched", async () => {
    const broken = { current: false };
    const h = createHarness({ wrapStore: (store) => flakyLoad(store, broken) });
    await h.settle();
    await createPasskeyWallet(h);
    await h.settle(); // flush the create commit's own echo-reload before arming the failure
    // An external commit triggers a reload whose load fails once.
    broken.current = true;
    await h.store.commit([{ op: "reset-failures" }]);
    await h.settle();
    expect(lastStatus(h).vault).toBe("unavailable");
    broken.current = false;
    // The next request retries the load once, recovers, and runs honestly.
    const unlocked = await h.call("vault.unlock", { factor: passkeyFactor() });
    expect("ok" in unlocked).toBe(true);
    expect(lastStatus(h).vault).toBe("unlocked");
  });

  it("a store that fails to load at startup is unavailable, not corrupted", async () => {
    const broken = { current: true };
    const h = createHarness({ wrapStore: (store) => flakyLoad(store, broken) });
    await h.settle();
    expect(lastStatus(h).vault).toBe("unavailable");
    expect(errCode(await h.call("nostr.generateKey", {}))).toBe("unavailable");
    broken.current = false;
    // The next request's reload restores health without any reset.
    const created = await h.call("wallet.createMnemonic", {
      words: 12,
      factor: { kind: "password", password: new Uint8Array(PASSWORD) },
    });
    expect("ok" in created).toBe(true);
  });

  it("a generic commit failure surfaces as unavailable", async () => {
    const broken = { current: true };
    const h = createHarness({ wrapStore: (store) => flakyCommit(store, broken) });
    await h.settle();
    const res = await h.call("wallet.importMnemonic", {
      mnemonic: utf8ToBytes(nip06.vectors[0]!.mnemonic),
      factor: { kind: "password", password: new Uint8Array(PASSWORD) },
    });
    expect(errCode(res)).toBe("unavailable");
    expect(lastStatus(h).vault).toBe("unavailable");
    broken.current = false;
    const retry = await h.call("wallet.importMnemonic", {
      mnemonic: utf8ToBytes(nip06.vectors[0]!.mnemonic),
      factor: { kind: "password", password: new Uint8Array(PASSWORD) },
    });
    expect("ok" in retry).toBe(true);
  });
});

describe("concurrent writers on one store", () => {
  /** A vault with password + passkey factors; both kernels hold unlocked sessions. */
  async function twoKernels(): Promise<{
    shared: ReturnType<typeof createMemoryStore>;
    a: Harness;
    b: Harness;
    sessionA: string;
    sessionB: string;
    passwordFactorId: string;
    passkeyFactorId: string;
  }> {
    const shared = createMemoryStore();
    const a = createHarness({ store: shared });
    await a.settle();
    const created = ok(
      await a.call("wallet.importMnemonic", {
        mnemonic: utf8ToBytes(nip06.vectors[0]!.mnemonic),
        factor: { kind: "password", password: new Uint8Array(PASSWORD) },
      }),
    );
    const sessionA = strField(created, "session");
    ok(
      await a.call(
        "vault.addFactor",
        {
          verify: { kind: "password", password: new Uint8Array(PASSWORD) },
          factor: passkeyFactor(),
        },
        sessionA,
      ),
    );
    const { factors } = lastStatus(a);
    const passwordFactorId = factorId(factors.find((f) => f.kind === "password"));
    const passkeyFactorId = factorId(factors.find((f) => f.kind === "passkey"));
    const b = createHarness({ store: shared });
    await b.settle();
    const unlockB = ok(
      await b.call("vault.unlock", {
        factor: { kind: "password", password: new Uint8Array(PASSWORD) },
      }),
    );
    return {
      shared,
      a,
      b,
      sessionA,
      sessionB: strField(unlockB, "session"),
      passwordFactorId,
      passkeyFactorId,
    };
  }

  it("concurrent removeFactor commits conflict — exactly one wins, one factor remains", async () => {
    const { shared, a, b, sessionA, sessionB, passwordFactorId, passkeyFactorId } =
      await twoKernels();
    // Each call needs its own verify object: the kernel wipes the password bytes it consumes.
    const [ra, rb] = await Promise.all([
      a.call(
        "vault.removeFactor",
        { verify: { kind: "password", password: new Uint8Array(PASSWORD) }, id: passkeyFactorId },
        sessionA,
      ),
      b.call(
        "vault.removeFactor",
        { verify: { kind: "password", password: new Uint8Array(PASSWORD) }, id: passwordFactorId },
        sessionB,
      ),
    ]);
    const codes = [ra, rb].map(codeOf);
    expect(codes.filter((c) => c === "ok")).toHaveLength(1);
    expect(codes.filter((c) => c === "conflict")).toHaveLength(1);
    const image = await shared.load();
    expect(image.factors.length).toBeGreaterThanOrEqual(1);
  });

  it("concurrent password addFactor commits conflict — one password factor remains", async () => {
    const { shared, a, b, sessionA, sessionB } = await twoKernels();
    const [ra, rb] = await Promise.all([
      a.call(
        "vault.addFactor",
        {
          verify: { kind: "password", password: new Uint8Array(PASSWORD) },
          factor: { kind: "password", password: utf8ToBytes("new password alpha") },
        },
        sessionA,
      ),
      b.call(
        "vault.addFactor",
        {
          verify: { kind: "password", password: new Uint8Array(PASSWORD) },
          factor: { kind: "password", password: utf8ToBytes("new password bravo") },
        },
        sessionB,
      ),
    ]);
    const codes = [ra, rb].map(codeOf);
    expect(codes.filter((c) => c === "ok")).toHaveLength(1);
    expect(codes.filter((c) => c === "conflict")).toHaveLength(1);
    const image = await shared.load();
    expect(image.factors.filter((f) => f.kind === "password")).toHaveLength(1);
  });
});
