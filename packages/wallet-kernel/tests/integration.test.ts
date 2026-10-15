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
import type { RecordStore } from "../src/vault/store.ts";
import type { KernelResponse } from "./harness.ts";
import { createHarness } from "./harness.ts";
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
    publicKey: strField(field(res, "nostr"), "publicKey"),
    walletId: strField(field(res, "wallet"), "walletId"),
  };
}

describe("create / import", () => {
  it("creates a passkey wallet matching the vector and opens a session", async () => {
    const h = createHarness();
    await h.settle();
    expect(field(ok(await h.call("status")), "vault")).toBe("uninitialized");

    const { session, publicKey, walletId } = await createPasskeyWallet(h);
    expect(session).toMatch(/^[0-9a-f]{32}$/);
    expect(publicKey).toBe(passkeyVector.vector.publicKey);
    expect(walletId).toBe(passkeyVector.vector.walletId);
    expect(npubEncode(publicKey)).toMatch(/^npub1/);

    const status = lastStatus(h);
    expect(status.vault).toBe("unlocked");
    expect(status.wallets[0]?.walletId).toBe(passkeyVector.vector.walletId);
    expect(status.wallets[0]?.backedUp).toBe(true);
    expect(status.nostrKeys[0]?.publicKey).toBe(publicKey);
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
    expect(strField(field(res, "nostr"), "publicKey")).toBe(nip06.vectors[0]!.publicKey);
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
    const { session, publicKey: pk0, walletId } = await createPasskeyWallet(h);

    const discovered = listField(
      ok(await h.call("wallet.discoverNostr", { walletId, from: 0, count: 3 }, session)),
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
    const { session, publicKey } = await createPasskeyWallet(h);
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
    const { session, publicKey: alice } = await createPasskeyWallet(h);
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
    const { session, publicKey } = await createPasskeyWallet(h);

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
    const { session, publicKey, walletId } = await createPasskeyWallet(h);
    const verify = {
      kind: "passkey",
      credentialId: CREDENTIAL_ID,
      prf: new Uint8Array(PRF_VAULT),
    };

    const exported = ok(await h.call("export.mnemonic", { verify, walletId }, session));
    expect(new TextDecoder().decode(exported as Uint8Array)).toBe(passkeyVector.vector.mnemonic);

    const nsecBytes = ok(
      await h.call(
        "export.nostrKey",
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
        "export.nostrKey",
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

    ok(await h.call("vault.lock"));
    const unlocked = ok(
      await h.call("vault.unlock", {
        factor: { kind: "passkey", credentialId: CREDENTIAL_ID, prf: new Uint8Array(PRF_VAULT) },
      }),
    );
    const session2 = strField(unlocked, "session");
    const afterLock = ok(await h.call("dataKeys.get", { purpose: "meowl-db" }, session2));
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

    // The new password factor can unlock after a lock.
    ok(await h.call("vault.lock"));
    const unlocked = ok(
      await h.call("vault.unlock", {
        factor: { kind: "password", password: new Uint8Array(PASSWORD) },
      }),
    );
    const session2 = strField(unlocked, "session");
    expect(lastStatus(h).vault).toBe("unlocked");

    // Removing with password verify works; the last factor cannot be removed.
    expect(
      ok(
        await h.call(
          "vault.removeFactor",
          { verify: { kind: "password", password: new Uint8Array(PASSWORD) }, id: addedId },
          session2,
        ),
      ),
    ).toBeNull();
    const lastId = factorId(lastStatus(h).factors[0]);
    expect(
      errCode(
        await h.call(
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

    ok(await h.call("vault.lock"));
    // The old password is a normal wrong-password failure; the new one opens the vault.
    expect(
      errCode(
        await h.call("vault.unlock", {
          factor: { kind: "password", password: utf8ToBytes("first correct horse") },
        }),
      ),
    ).toBe("wrong-password");
    const unlocked = ok(
      await h.call("vault.unlock", {
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
    // A host store that suppresses change notices for the kernel's own commits: the
    // commit path itself must reload the image and drop the session.
    const h = createHarness({
      wrapStore: (store) => ({
        load: async () => store.load(),
        commit: async (ops) => store.commit(ops),
        watch: () => () => {},
      }),
    });
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

  it("locks: session methods return locked and a locked event is emitted", async () => {
    const h = createHarness();
    await h.settle();
    const { session } = await createPasskeyWallet(h);
    ok(await h.call("vault.lock"));
    expect(lastStatus(h).vault).toBe("locked");
    expect(lockReasons(h.events)).toContain("user");
    expect(errCode(await h.call("nostr.createNip46ClientKey", null, session))).toBe("locked");
    // A stale session id is rejected even after re-unlock.
    const unlocked = ok(
      await h.call("vault.unlock", {
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

  it("deletes a wallet and its derived keys", async () => {
    const h = createHarness();
    await h.settle();
    const { session, walletId } = await createPasskeyWallet(h);
    ok(await h.call("nostr.deriveKey", { walletId, groupIndex: 5 }, session));
    expect(lastStatus(h).nostrKeys).toHaveLength(2);
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
    expect(status.nostrKeys).toHaveLength(0);
    expect(errCode(await h.call("nostr.deriveKey", { walletId, groupIndex: 6 }, session))).toBe(
      "not-found",
    );
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

  it("rate limits wrong passwords: 30s, 60s, 300s, then resets on success", async () => {
    const h = createHarness();
    await h.settle();
    const { session } = await createPasskeyWallet(h);
    const verify = { kind: "passkey", credentialId: CREDENTIAL_ID, prf: new Uint8Array(PRF_VAULT) };
    ok(
      await h.call(
        "vault.addFactor",
        { verify, factor: { kind: "password", password: new Uint8Array(PASSWORD) } },
        session,
      ),
    );
    ok(await h.call("vault.lock"));

    const bad = async () =>
      h.call("vault.unlock", { factor: { kind: "password", password: utf8ToBytes("wrong pass") } });

    // Failures 1-4: wrong-password, no rate limit.
    for (let i = 0; i < 4; i++) {
      // oxlint-disable-next-line eslint/no-await-in-loop -- unlock attempts are sequential by design
      expect(errCode(await bad())).toBe("wrong-password");
    }
    // 5th failure arms the 30 s backoff.
    expect(errCode(await bad())).toBe("wrong-password");
    const limited = await bad();
    expect(errCode(limited)).toBe("rate-limited");
    expect(errPayload(limited).retryAt).toBeGreaterThan(0);
    h.advance(31_000);
    // Failure #6 → 60 s backoff; #7 → 300 s.
    expect(errCode(await bad())).toBe("wrong-password");
    expect(errCode(await bad())).toBe("rate-limited");
    h.advance(61_000);
    expect(errCode(await bad())).toBe("wrong-password");
    expect(errCode(await bad())).toBe("rate-limited");
    h.advance(301_000);
    // Success resets the counter.
    const unlocked = await h.call("vault.unlock", {
      factor: { kind: "password", password: new Uint8Array(PASSWORD) },
    });
    expect("ok" in unlocked).toBe(true);
    // Failing again starts at 1, not where we left off.
    ok(await h.call("vault.lock"));
    expect(errCode(await bad())).toBe("wrong-password");
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
    await createPasskeyWallet(h);
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

  it("a racing establish fails with integrity and writes nothing", async () => {
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
    await h.store.commit([
      { op: "expect-uninitialized" },
      { op: "put-meta", meta: { format: 1, failedAttempts: 0, retryAt: 0 } },
    ]);
    await h.settle();

    const answers = quiz.map((p) => utf8ToBytes(words[p]!));
    const res = await h.call("wallet.confirmMnemonic", { draft, answers });
    expect(errCode(res)).toBe("integrity");
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
