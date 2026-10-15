/**
 * Phase C kernel probe: run the wallet-worker Hermes smoke flow inside the kernel runtime with the
 * real native platform — __qntx.random/now/setTimer and native pbkdf2 off the kernel thread — plus
 * a memory store and an in-memory port. Reports per-step timings (mnemonic import → first
 * signature, password lock/unlock at 600k PBKDF2-SHA256, BIP-39 seed native vs noble, schnorr sign,
 * NIP-44 round trip) and pass/fail.
 */
// globals.ts MUST evaluate before every other module: it installs TextDecoder and a crypto shim
// that the kernel and noble touch at module scope or first use. Keep this import first.
import {
  hermesGlobalsInstalled,
  missingGlobals,
  shimmedGlobals,
} from "../../../packages/wallet-worker/tests/hermes/globals.ts";

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
  const platform: KernelPlatform = {
    random: (n) => __qntx.random(n),
    now: () => __qntx.now(),
    setTimer: (ms, fn) => __qntx.setTimer(ms, fn),
    pbkdf2,
    store: createMemoryStore(),
    policy: { idleMs: 15 * 60_000, maxSessionMs: 12 * 3_600_000 },
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

function ok(value: Reply): ProtocolValue {
  if (value.err !== undefined) {
    throw new Error(`kernel: call failed ${value.err.code}`);
  }
  if (value.ok === undefined) {
    throw new Error("kernel: response carried neither ok nor err");
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

async function pbkdf2Vectors(): Promise<Record<string, number>> {
  const timings: Record<string, number> = {};

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

  // BIP-39 seed shape: sha512, 2048 rounds, 64 bytes — native vs pure-JS timing.
  const seedPassword = utf8ToBytes(`${MNEMONIC} `.normalize("NFKD"));
  const seedSalt = utf8ToBytes("mnemonic".normalize("NFKD"));
  let t0 = __qntx.now();
  const jsSeed = await noblePbkdf2("sha512", seedPassword, seedSalt, 2048, 64);
  timings["pbkdf2-bip39-js"] = __qntx.now() - t0;
  t0 = __qntx.now();
  const nativeSeed = await nativePbkdf2("sha512", seedPassword, seedSalt, 2048, 64);
  timings["pbkdf2-bip39-native"] = __qntx.now() - t0;
  eq(bytesToHex(nativeSeed), bytesToHex(jsSeed), "pbkdf2 bip39 seed");

  // Unlock-scale benchmark: the password factor KEK is 600k PBKDF2-SHA256.
  t0 = __qntx.now();
  await nativePbkdf2("sha256", utf8ToBytes(PASSWORD), utf8ToBytes("v1-bench"), 600_000, 32);
  timings["pbkdf2-600k-sha256"] = __qntx.now() - t0;
  return timings;
}

async function main(): Promise<void> {
  if (!hermesGlobalsInstalled) {
    throw new Error("globals module did not evaluate first");
  }
  // The shimmed crypto.getRandomValues is test-grade xorshift — upgrade it to the real native
  // entropy source now that __qntx is available.
  crypto.getRandomValues = <T extends { length: number; [k: number]: number }>(arr: T): T => {
    arr.set(__qntx.random(arr.length).subarray(0, arr.length) as never);
    return arr;
  };

  const timings: Record<string, number> = {};
  Object.assign(timings, await pbkdf2Vectors());

  const kernel = boot(nativePbkdf2);

  // Mnemonic import (password factor → vault + session), NIP-06 derive, first signature.
  let t0 = __qntx.now();
  const imported = ok(
    await kernel.call("wallet.importMnemonic", {
      mnemonic: utf8ToBytes(MNEMONIC),
      factor: { kind: "password", password: utf8ToBytes(PASSWORD) },
    }),
  );
  const walletId = field(field(imported, "wallet"), "walletId");
  const sessionValue = field(imported, "session");
  assert(typeof sessionValue === "string" && sessionValue.length === 32, "importMnemonic session");
  let session = sessionValue;
  const derived = ok(await kernel.call("nostr.deriveKey", { walletId, groupIndex: 0 }, session));
  eq(field(derived, "publicKey"), EXPECTED_PUBLIC_KEY, "deriveKey public key");
  const signed = ok(
    await kernel.call(
      "nostr.signEvent",
      {
        publicKey: EXPECTED_PUBLIC_KEY,
        event: {
          kind: 1,
          created_at: Math.floor(__qntx.now() / 1000),
          tags: [["t", "hermes"]],
          content: "hello from v1 kernel",
        },
      },
      session,
    ),
  );
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- result validator guarantees Event
  const event = signed as Event;
  eq(event.pubkey, EXPECTED_PUBLIC_KEY, "signEvent pubkey");
  assert(verifyEvent(event), "signEvent verifies");
  timings["import-to-first-sign"] = __qntx.now() - t0;

  // Password factor lock/unlock — 600k PBKDF2-SHA256 through the native KDF.
  t0 = __qntx.now();
  await kernel.call("vault.lock", null, session);
  const unlocked = ok(
    await kernel.call("vault.unlock", {
      factor: { kind: "password", password: utf8ToBytes(PASSWORD) },
    }),
  );
  const unlockSession = field(unlocked, "session");
  assert(typeof unlockSession === "string" && unlockSession.length === 32, "unlock session");
  session = unlockSession;
  timings["password-lock-unlock"] = __qntx.now() - t0;

  // NIP-44 round trip against a fixed peer.
  t0 = __qntx.now();
  const ciphertext = ok(
    await kernel.call(
      "nostr.nip44Encrypt",
      { publicKey: EXPECTED_PUBLIC_KEY, peer: PEER_PUBLIC_KEY, text: "v1 kernel nip44" },
      session,
    ),
  );
  assert(typeof ciphertext === "string" && ciphertext.length > 0, "nip44Encrypt payload");
  const plaintext = ok(
    await kernel.call(
      "nostr.nip44Decrypt",
      { publicKey: EXPECTED_PUBLIC_KEY, peer: PEER_PUBLIC_KEY, text: ciphertext },
      session,
    ),
  );
  eq(plaintext, "v1 kernel nip44", "nip44 round trip");
  timings["nip44-round-trip"] = __qntx.now() - t0;

  // nsec export — re-verifies with the password factor (another 600k native PBKDF2).
  t0 = __qntx.now();
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
  );
  assert(nsecBytes instanceof Uint8Array, "nostr.exportKey bytes");
  eq(new TextDecoder().decode(nsecBytes), EXPECTED_NSEC, "nostr.exportKey nsec");
  timings["export-nsec"] = __qntx.now() - t0;

  const statusEvents = kernel.posted.filter(
    (m) => typeof m === "object" && m !== null && !Array.isArray(m) && "event" in m,
  );
  assert(statusEvents.length > 0, "kernel posted status events");

  postJson({
    kind: "done",
    pass: true,
    pbkdf2: "native",
    missingGlobals: [...missingGlobals],
    shimmedGlobals: [...shimmedGlobals],
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
