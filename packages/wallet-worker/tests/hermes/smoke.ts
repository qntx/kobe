/**
 * Hermes smoke test for the wallet kernel: bundled to a single classic script and run on the bare
 * Hermes CLI that RN 0.88 ships (hermes-v260318099.0.4). Everything the kernel needs from its host
 * is injected — deterministic random, fake clock, pure-JS PBKDF2, a never-firing setTimer stub, an
 * in-memory store, and an in-memory port — so the only ambient requirements left are the globals
 * globals.ts reports and shims.
 *
 * Hard asserts only; entry.ts prints `HERMES_SMOKE_OK` after every check — including async ones —
 * settled. The OK line is the pass contract: Hermes exits 0 even for unhandled async errors, so
 * runners must assert the marker appears in stdout.
 */
import { pbkdf2Async } from "@noble/hashes/pbkdf2.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";

import { verifyEvent } from "@qntx/nostr";
import type { Event } from "@qntx/nostr";
import { createMemoryStore, startKernel } from "@qntx/wallet-kernel";
import type { KernelPlatform, Pbkdf2, Port, Random } from "@qntx/wallet-kernel";
import type { ProtocolValue, WalletErrorCode } from "@qntx/wallet/protocol";

// vectors/wallet/nip06.json — NIP-06 derivation path m/44'/1237'/0'/0/0.
const MNEMONIC = "leader monkey parrot ring guide accident before fence cannon height naive bean";
const EXPECTED_PUBLIC_KEY = "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917";
const EXPECTED_NSEC = "nsec10allq0gjx7fddtzef0ax00mdps9t2kmtrldkyjfs8l5xruwvh2dq0lhhkp";
const PASSWORD = "correct horse battery staple";
// vectors/nip44/official.json — a fixed peer for the encrypt/decrypt round trip.
const PEER_PUBLIC_KEY = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

function assert(cond: boolean, name: string): asserts cond {
  if (!cond) {
    throw new Error(`smoke: ${name}`);
  }
}
function eq<T>(got: T, want: T, name: string): void {
  if (JSON.stringify(got) !== JSON.stringify(want)) {
    throw new Error(`smoke: ${name}: got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);
  }
}

/** Mulberry32: small deterministic PRNG for the injected platform.random. */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a += 0x6d2b79f5;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const nextFloat = mulberry32(1);
const random: Random = (length) => {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    out[i] = Math.floor(nextFloat() * 256);
  }
  return out;
};

/** Pure-JS PBKDF2 — Hermes has no WebCrypto; production RN injects a native KDF the same way. */
const noblePbkdf2: Pbkdf2 = async (hash, password, salt, iterations, length) =>
  pbkdf2Async(hash === "sha256" ? sha256 : sha512, password, salt, {
    c: iterations,
    dkLen: length,
  });

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

function boot(store: ReturnType<typeof createMemoryStore>): Kernel {
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
    random,
    now: () => 1_700_000_000_000,
    elapsed: () => 0,
    // The session's idle/max timers simply never fire in this smoke — no ambient clock advances.
    setTimer: () => () => undefined,
    pbkdf2: noblePbkdf2,
    store,
    policy: {
      idleMs: 15 * 60_000,
      maxSessionMs: 12 * 3_600_000,
      maxScryptLogN: 20,
      activity: "request",
    },
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

function ok(value: { ok?: ProtocolValue; err?: { code: WalletErrorCode } }): ProtocolValue {
  if (value.err !== undefined) {
    throw new Error(`smoke: kernel error ${value.err.code}`);
  }
  if (value.ok === undefined) {
    throw new Error("smoke: response carried neither ok nor err");
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

export async function main(): Promise<void> {
  const store = createMemoryStore();
  const kernel = boot(store);

  // 1. Import the NIP-06 mnemonic with a password factor → wallet + session, then derive the
  // group-0 key through the nostr module.
  const imported = ok(
    await kernel.call("wallet.importMnemonic", {
      mnemonic: utf8ToBytes(MNEMONIC),
      factor: { kind: "password", password: utf8ToBytes(PASSWORD) },
    }),
  );
  const walletId = field(field(imported, "wallet"), "walletId");
  const sessionValue = field(imported, "session");
  assert(typeof sessionValue === "string" && sessionValue.length === 32, "importMnemonic session");
  const derived = ok(
    await kernel.call("nostr.deriveKey", { walletId, groupIndex: 0 }, sessionValue),
  );
  eq(field(derived, "publicKey"), EXPECTED_PUBLIC_KEY, "deriveKey public key");

  // 2./3. A lock is host-side (the worker dies and respawns): booting a fresh kernel over the
  // same store is the locked enclave — unlock with the password → a fresh session.
  const kernel2 = boot(store);
  const unlocked = ok(
    await kernel2.call("vault.unlock", {
      factor: { kind: "password", password: utf8ToBytes(PASSWORD) },
    }),
  );
  const unlockSession = field(unlocked, "session");
  assert(typeof unlockSession === "string" && unlockSession.length === 32, "unlock session");
  const session = unlockSession;

  // 4. Sign an event with the derived key — the schnorr signature must verify.
  const signed = ok(
    await kernel2.call(
      "nostr.signEvent",
      {
        publicKey: EXPECTED_PUBLIC_KEY,
        event: {
          kind: 1,
          created_at: 1_700_000_000,
          tags: [["t", "hermes"]],
          content: "hello from bare hermes",
        },
      },
      session,
    ),
  );
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- result validator guarantees the Event shape
  const event = signed as Event;
  eq(event.pubkey, EXPECTED_PUBLIC_KEY, "signEvent pubkey");
  assert(verifyEvent(event), "signEvent verifies");

  // 5./6. NIP-44 round trip against a fixed peer.
  const ciphertext = ok(
    await kernel2.call(
      "nostr.nip44Encrypt",
      { publicKey: EXPECTED_PUBLIC_KEY, peer: PEER_PUBLIC_KEY, text: "hermes nip44" },
      session,
    ),
  );
  assert(typeof ciphertext === "string" && ciphertext.length > 0, "nip44Encrypt payload");
  const plaintext = ok(
    await kernel2.call(
      "nostr.nip44Decrypt",
      { publicKey: EXPECTED_PUBLIC_KEY, peer: PEER_PUBLIC_KEY, text: ciphertext },
      session,
    ),
  );
  eq(plaintext, "hermes nip44", "nip44 round trip");

  // 7. Export the key in nsec format — re-verifies with the password factor.
  const nsecBytes = ok(
    await kernel2.call(
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
  const nsec = new TextDecoder().decode(nsecBytes);
  eq(nsec, EXPECTED_NSEC, "nostr.exportKey nsec");

  const statusEvents = kernel2.posted.filter(
    (m) => typeof m === "object" && m !== null && !Array.isArray(m) && "event" in m,
  );
  assert(statusEvents.length > 0, "kernel posted status events");
}
