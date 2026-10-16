/**
 * Phase C kernel probe: run the wallet-worker Hermes smoke flow inside the kernel runtime with the
 * real native platform — __qntx.random/now/elapsed/setTimer, native crypto.getRandomValues and
 * TextDecoder, and pbkdf2 on the KDF worker thread — plus a memory store and an in-memory port.
 * Reports per-step timings (mnemonic import → first signature, password lock/unlock at 600k
 * PBKDF2-SHA256, BIP-39 seed native vs noble, schnorr sign, NIP-44 round trip) and pass/fail.
 */

import { pbkdf2Async } from "@noble/hashes/pbkdf2.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";

import { verifyEvent } from "@qntx/nostr";
import type { Event } from "@qntx/nostr";
import { createMemoryStore, startKernel } from "../../../packages/wallet-kernel/src/index.ts";
import type {
  KernelPlatform,
  Pbkdf2,
  Port,
} from "../../../packages/wallet-kernel/src/platform.ts";
import type { ProtocolValue, WalletErrorCode } from "../../../packages/wallet/src/protocol/index.ts";

import { postJson } from "./share.ts";

// vectors/wallet/nip06.json — NIP-06 derivation path m/44'/1237'/0'/0/0.
const MNEMONIC = "leader monkey parrot ring guide accident before fence cannon height naive bean";
const EXPECTED_PUBLIC_KEY = "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917";
const EXPECTED_NSEC = "nsec10allq0gjx7fddtzef0ax00mdps9t2kmtrldkyjfs8l5xruwvh2dq0lhhkp";
const PASSWORD = "correct horse battery staple";
// vectors/nip44/official.json — a fixed peer for the encrypt/decrypt round trip.
const PEER_PUBLIC_KEY = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

function assert(cond: boolean, name: string): asserts cond {
  if (!cond) {
    throw new Error(`kernel: ${name}`);
  }
}
function eq<T>(got: T, want: T, name: string): void {
  if (JSON.stringify(got) !== JSON.stringify(want)) {
    throw new Error(`kernel: ${name}: got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);
  }
}

type Reply = {
  readonly ok?: ProtocolValue;
  readonly err?: { readonly code: WalletErrorCode; readonly retryAt?: number };
};

type Kernel = {
  readonly call: (
    method: string,
    params: unknown,
    session?: string,
  ) => Promise<{ readonly ok?: ProtocolValue; readonly err?: { readonly code: WalletErrorCode } }>;
  readonly posted: ReadonlyArray<ProtocolValue>;
};

function boot(pbkdf2: Pbkdf2): Kernel {
  const posted: ProtocolValue[] = [];
  const pending = new Map<number, (reply: Reply) => void>();
  let handler: ((message: unknown) => void) | undefined;
  const port: Port = {
    post: (message) => {
      posted.push(message);
      if (
        typeof message !== "object" ||
        message === null ||
        Array.isArray(message) ||
        message instanceof Uint8Array ||
        !("id" in message)
      ) {
        return;
      }
      const { id } = message;
      if (typeof id !== "number") {
        return;
      }
      const resolve = pending.get(id);
      if (resolve !== undefined) {
        pending.delete(id);
        resolve(message);
      }
    },
    listen: (h) => {
      handler = h;
      return () => {
        handler = undefined;
      };
    },
  };
  const store = createMemoryStore();
  const platform: KernelPlatform = {
    random: (n) => __qntx.random(n),
    now: () => __qntx.now(),
    elapsed: () => __qntx.elapsed(),
    setTimer: (ms, fn) => __qntx.setTimer(ms, fn),
    pbkdf2,
    store,
    policy: { idleMs: 15 * 60_000, maxSessionMs: 12 * 3_600_000, maxScryptLogN: 18 },
  };
  startKernel(platform, port);

  let nextId = 1;
  return {
    posted,
    call: async (method, params, session) =>
      new Promise((resolve) => {
        const id = nextId++;
        pending.set(id, resolve);
        handler?.({ v: 1, id, method, session, params: params ?? null });
      }),
  };
}

function ok(value: Reply, name: string): ProtocolValue {
  if (value.err !== undefined) {
    throw new Error(`kernel: ${name} failed ${value.err.code}`);
  }
  if (value.ok === undefined) {
    throw new Error(`kernel: ${name} response carried neither ok nor err`);
  }
  return value.ok;
}

function field(value: ProtocolValue, name: string): ProtocolValue {
  assert(
    typeof value === "object" &&
      value !== null &&
      !Array.isArray(value) &&
      !(value instanceof Uint8Array),
    `field ${name}: not an object`,
  );
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- narrowed to a record above
  const result = (value as Record<string, ProtocolValue>)[name];
  assert(result !== undefined, `field ${name}: absent`);
  return result;
}

const nativePbkdf2: Pbkdf2 = (hash, password, salt, iterations, length) =>
  new Promise((resolve, reject) => {
    __qntx.pbkdf2(hash, password, salt, iterations, length, (result, error) => {
      if (error !== undefined || result === undefined) {
        reject(new Error(error ?? "pbkdf2 returned nothing"));
      } else {
        resolve(result);
      }
    });
  });

const noblePbkdf2: Pbkdf2 = (hash, password, salt, iterations, length) =>
  pbkdf2Async(hash === "sha256" ? sha256 : sha512, password, salt, { c: iterations, dkLen: length });

// Batches `n` iterations of `op` and reports total + per-op milliseconds on
// __qntx.elapsed (fractional ms — a single signature is far below now()'s 1 ms).
async function batch(
  n: number,
  op: (index: number) => Promise<void>,
): Promise<{ readonly n: number; readonly totalMs: number; readonly perOpMs: number }> {
  const t0 = __qntx.elapsed();
  for (let i = 0; i < n; i++) {
    await op(i);
  }
  const totalMs = __qntx.elapsed() - t0;
  return { n, totalMs, perOpMs: totalMs / n };
}

const median = (xs: number[]): number => {
  const s = [...xs].sort((a, b) => a - b);
  return s.length === 0 ? 0 : (s[Math.floor((s.length - 1) / 2)] ?? 0);
};

async function pbkdf2Vectors(): Promise<Record<string, unknown>> {
  const timings: Record<string, unknown> = {};

  // RFC PBKDF2-HMAC-SHA256 reference vector: "passwd"/"salt"/1/64.
  const rfc = await nativePbkdf2("sha256", utf8ToBytes("passwd"), utf8ToBytes("salt"), 1, 64);
  eq(
    bytesToHex(rfc),
    "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc" +
      "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
    "pbkdf2 RFC vector",
  );

  const vectors = [
    { hash: "sha256" as const, password: utf8ToBytes("password"), salt: utf8ToBytes("salt"), c: 1000, len: 32 },
    { hash: "sha512" as const, password: utf8ToBytes("pässwörd 🔑"), salt: utf8ToBytes("salt-✓"), c: 777, len: 48 },
    { hash: "sha256" as const, password: utf8ToBytes("pw"), salt: new Uint8Array(0), c: 64, len: 32 },
  ];
  for (const v of vectors) {
    const js = await noblePbkdf2(v.hash, v.password, v.salt, v.c, v.len);
    const native = await nativePbkdf2(v.hash, v.password, v.salt, v.c, v.len);
    eq(bytesToHex(native), bytesToHex(js), `pbkdf2 vector ${v.hash}/${v.c}`);
  }

  // BIP-39 seed shape: sha512, 2048 rounds, 64 bytes — native vs pure-JS timing, 10 each.
  const seedPassword = utf8ToBytes(`${MNEMONIC} `.normalize("NFKD"));
  const seedSalt = utf8ToBytes("mnemonic".normalize("NFKD"));
  const jsSeed = await noblePbkdf2("sha512", seedPassword, seedSalt, 2048, 64);
  const nativeSeed = await nativePbkdf2("sha512", seedPassword, seedSalt, 2048, 64);
  eq(bytesToHex(nativeSeed), bytesToHex(jsSeed), "pbkdf2 bip39 seed");
  timings["pbkdf2-bip39-js"] = await batch(10, async () => {
    await noblePbkdf2("sha512", seedPassword, seedSalt, 2048, 64);
  });
  timings["pbkdf2-bip39-native"] = await batch(10, async () => {
    await nativePbkdf2("sha512", seedPassword, seedSalt, 2048, 64);
  });

  // Unlock-scale benchmark: the password factor KEK is 600k PBKDF2-SHA256.
  const t0 = __qntx.elapsed();
  await nativePbkdf2("sha256", utf8ToBytes(PASSWORD), utf8ToBytes("v1-bench"), 600_000, 32);
  timings["pbkdf2-600k-sha256"] = __qntx.elapsed() - t0;
  return timings;
}

async function main(): Promise<void> {
  const timings: Record<string, unknown> = {};
  Object.assign(timings, await pbkdf2Vectors());

  const kernel = boot(nativePbkdf2);

  // Mnemonic import (password factor → vault + session), NIP-06 derive, first signature.
  let t0 = __qntx.elapsed();
  const imported = ok(
    await kernel.call("wallet.importMnemonic", {
      mnemonic: utf8ToBytes(MNEMONIC),
      factor: { kind: "password", password: utf8ToBytes(PASSWORD) },
    }),
    "importMnemonic",
  );
  const walletId = field(field(imported, "wallet"), "walletId");
  const sessionValue = field(imported, "session");
  assert(typeof sessionValue === "string" && sessionValue.length === 32, "importMnemonic session");
  let session = sessionValue;
  const derived = ok(
    await kernel.call("nostr.deriveKey", { walletId, groupIndex: 0 }, session),
    "nostr.deriveKey",
  );
  eq(field(derived, "publicKey"), EXPECTED_PUBLIC_KEY, "deriveKey public key");
  const signParams = {
    publicKey: EXPECTED_PUBLIC_KEY,
    event: {
      kind: 1,
      created_at: Math.floor(__qntx.now() / 1000),
      tags: [["t", "hermes"]],
      content: "hello from v1 kernel",
    },
  };
  const signed = ok(
    await kernel.call("nostr.signEvent", signParams, session),
    "nostr.signEvent",
  );
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- result validator guarantees Event
  const event = signed as Event;
  eq(event.pubkey, EXPECTED_PUBLIC_KEY, "signEvent pubkey");
  assert(verifyEvent(event), "signEvent verifies");
  timings["import-to-first-sign"] = __qntx.elapsed() - t0;

  // 100 schnorr signatures through the kernel — sub-ms ops only register on elapsed().
  timings["sign-event-100"] = await batch(100, async (i) => {
    const again = ok(
      await kernel.call(
        "nostr.signEvent",
        { ...signParams, event: { ...signParams.event, content: `v1 kernel sign ${i}` } },
        session,
      ),
      "nostr.signEvent batch",
    );
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- result validator guarantees Event
    assert(verifyEvent(again as Event), "signEvent batch verifies");
  });

  // Password factor unlock — 600k PBKDF2-SHA256 through the native KDF. First unlock is
  // reported alone; three repeats give min/median for the steady-state number.
  t0 = __qntx.elapsed();
  const unlockCalls = async (): Promise<void> => {
    const unlocked = ok(
      await kernel.call("vault.unlock", {
        factor: { kind: "password", password: utf8ToBytes(PASSWORD) },
      }),
      "vault.unlock",
    );
    const unlockSession = field(unlocked, "session");
    assert(typeof unlockSession === "string" && unlockSession.length === 32, "unlock session");
    session = unlockSession;
  };
  await unlockCalls();
  timings["password-unlock"] = __qntx.elapsed() - t0;
  const unlockRepeats: number[] = [];
  for (let i = 0; i < 3; i++) {
    const t = __qntx.elapsed();
    await unlockCalls();
    unlockRepeats.push(__qntx.elapsed() - t);
  }
  timings["password-unlock-repeats"] = {
    n: unlockRepeats.length,
    min: Math.min(...unlockRepeats),
    median: median(unlockRepeats),
  };

  // 100 NIP-44 encrypt+decrypt round trips against a fixed peer.
  const nip44Peer = { publicKey: EXPECTED_PUBLIC_KEY, peer: PEER_PUBLIC_KEY };
  const firstCipher = ok(
    await kernel.call("nostr.nip44Encrypt", { ...nip44Peer, text: "v1 kernel nip44" }, session),
    "nostr.nip44Encrypt",
  );
  assert(typeof firstCipher === "string" && firstCipher.length > 0, "nip44Encrypt payload");
  timings["nip44-round-trip-100"] = await batch(100, async (i) => {
    const text = `v1 kernel nip44 ${i}`;
    const ciphertext = ok(
      await kernel.call("nostr.nip44Encrypt", { ...nip44Peer, text }, session),
      "nostr.nip44Encrypt batch",
    );
    const plaintext = ok(
      await kernel.call(
        "nostr.nip44Decrypt",
        { ...nip44Peer, text: ciphertext },
        session,
      ),
      "nostr.nip44Decrypt batch",
    );
    eq(plaintext, text, "nip44 batch round trip");
  });
  const finalCheck = ok(
    await kernel.call(
      "nostr.nip44Decrypt",
      { ...nip44Peer, text: firstCipher },
      session,
    ),
    "nostr.nip44Decrypt",
  );
  eq(finalCheck, "v1 kernel nip44", "nip44 round trip");

  // nsec export — re-verifies with the password factor (another 600k native PBKDF2).
  t0 = __qntx.elapsed();
  const nsecBytes = ok(
    await kernel.call(
      "nostr.exportKey",
      {
        verify: { kind: "password", password: utf8ToBytes(PASSWORD) },
        publicKey: EXPECTED_PUBLIC_KEY,
        format: { kind: "nsec" },
      },
      session,
    ),
    "nostr.exportKey",
  );
  assert(nsecBytes instanceof Uint8Array, "nostr.exportKey bytes");
  eq(new TextDecoder().decode(nsecBytes), EXPECTED_NSEC, "nostr.exportKey nsec");
  timings["export-nsec"] = __qntx.elapsed() - t0;

  const statusEvents = kernel.posted.filter(
    (m) => typeof m === "object" && m !== null && !Array.isArray(m) && "event" in m,
  );
  assert(statusEvents.length > 0, "kernel posted status events");

  postJson({
    kind: "done",
    pass: true,
    pbkdf2: "native",
    timings,
  });
}

try {
  postJson({ kind: "kernel-ready" });
  main().catch((error: unknown) => {
    postJson({
      kind: "done",
      pass: false,
      error: error instanceof Error ? `${error.name}: ${error.message}` : String(error),
    });
  });
} catch (error: unknown) {
  postJson({ kind: "done", pass: false, error: String(error) });
}
