import type { KernelEvent, ProtocolValue } from "@qntx/wallet/protocol";
import type { WalletErrorCode } from "@qntx/wallet/types";

import { startKernel } from "../src/kernel.ts";
import type { KernelPlatform, Port, Random } from "../src/platform.ts";
import { createMemoryStore } from "../src/vault/memory.ts";
import type { RecordStore } from "../src/vault/store.ts";
import { subtlePbkdf2 } from "./helpers.ts";

/** Mulberry32: small deterministic PRNG for tests only. */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a += 0x6d2b79f5;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Deterministic Random over a mulberry32 stream; records every draw for the leak check. */
export function seededRandom(seed: number): { random: Random; draws: Uint8Array[] } {
  const next = mulberry32(seed);
  const draws: Uint8Array[] = [];
  return {
    random: (length: number) => {
      const out = new Uint8Array(length);
      for (let i = 0; i < length; i++) {
        out[i] = Math.floor(next() * 256);
      }
      draws.push(new Uint8Array(out));
      return out;
    },
    draws,
  };
}

export type KernelResponse =
  | { readonly id: number; readonly ok: ProtocolValue }
  | {
      readonly id: number;
      readonly err: { readonly code: WalletErrorCode; readonly retryAt?: number };
    };

export type Harness = {
  readonly call: (method: string, params?: unknown, session?: string) => Promise<KernelResponse>;
  /** Every message the kernel posted, in order. */
  readonly posted: ProtocolValue[];
  readonly events: KernelEvent[];
  /** The raw shared store — direct commits simulate an external writer. */
  readonly store: RecordStore;
  readonly draws: Uint8Array[];
  /** Advances the monotonic elapsed clock (session deadlines, timers). */
  readonly advance: (ms: number) => void;
  /** Moves the wall clock by `ms` — may be negative (persisted timestamps, backoff). */
  readonly advanceWall: (ms: number) => void;
  /** The current wall-clock reading (`platform.now()`). */
  readonly wallNow: () => number;
  readonly settle: () => Promise<void>;
  /** Sends a raw (possibly malformed) message to the kernel and awaits its response. */
  readonly sendRaw: (raw: unknown) => Promise<KernelResponse>;
};

/**
 * Like the real Web/Node stores: a watcher never fires for commits made through the same
 * RecordStore instance — only for other writers'. Kernel `commit` reloads explicitly, so the kernel
 * never relies on its own echo.
 */
export function nonEchoing(store: RecordStore): RecordStore {
  let ownCommits = 0;
  return {
    load: async () => store.load(),
    commit: async (ops) => {
      ownCommits++;
      try {
        await store.commit(ops);
      } catch (error) {
        ownCommits--; // a failed commit fires no watch — do not eat the next external notice
        throw error;
      }
    },
    watch: (listener) =>
      store.watch(() => {
        if (ownCommits > 0) {
          ownCommits--;
          return;
        }
        listener();
      }),
  };
}

function isResponse(message: ProtocolValue): message is {
  id: number;
  ok?: ProtocolValue;
  err?: { code: WalletErrorCode; retryAt?: number };
} {
  return (
    typeof message === "object" &&
    message !== null &&
    !Array.isArray(message) &&
    !(message instanceof Uint8Array) &&
    "id" in message &&
    ("ok" in message || "err" in message)
  );
}

function isEvent(message: ProtocolValue): message is KernelEvent & ProtocolValue {
  return (
    typeof message === "object" &&
    message !== null &&
    !Array.isArray(message) &&
    !(message instanceof Uint8Array) &&
    "event" in message
  );
}

export function createHarness(opts?: {
  seed?: number;
  start?: number;
  idleMs?: number;
  maxSessionMs?: number;
  /** Share one store between harnesses (the raw store — each kernel still gets its own view). */
  store?: RecordStore;
  /** Wrap the kernel's store view (e.g. `nonEchoing` so own commits do not self-notify). */
  wrapStore?: ((store: RecordStore) => RecordStore) | undefined;
}): Harness {
  let now = opts?.start ?? 1_700_000_000_000; // wall clock — persisted timestamps only
  let elapsed = 0; // monotonic clock — session deadlines and timers
  const { random, draws } = seededRandom(opts?.seed ?? 1);
  const inner = opts?.store ?? createMemoryStore();
  const store = opts?.wrapStore === undefined ? inner : opts.wrapStore(inner);
  const posted: ProtocolValue[] = [];
  const events: KernelEvent[] = [];
  const pending = new Map<number, (response: KernelResponse) => void>();
  const timers: Array<{ fireAt: number; fn: () => void }> = [];
  let handler: ((message: unknown) => void) | undefined;

  const port: Port = {
    post: (message) => {
      posted.push(message);
      if (isResponse(message)) {
        const resolve = pending.get(message.id);
        if (resolve !== undefined) {
          pending.delete(message.id);
          const { ok, err } = message;
          resolve(
            ok !== undefined || err === undefined
              ? { id: message.id, ok: ok ?? null }
              : { id: message.id, err },
          );
        }
      } else if (isEvent(message)) {
        events.push(message);
      }
    },
    listen: (h) => {
      handler = h;
      return () => {
        handler = undefined;
      };
    },
  };

  const takeDueTimer = (): { fn: () => void } | undefined => {
    timers.sort((a, b) => a.fireAt - b.fireAt);
    const due = timers.findIndex((t) => t.fireAt <= elapsed);
    return due === -1 ? undefined : timers.splice(due, 1)[0];
  };

  const platform: KernelPlatform = {
    random,
    now: () => now,
    elapsed: () => elapsed,
    // Fake timers driven by the monotonic clock: `advance` fires everything that came due.
    setTimer: (delayMs, fn) => {
      const entry = { fireAt: elapsed + delayMs, fn };
      timers.push(entry);
      return () => {
        const index = timers.indexOf(entry);
        if (index !== -1) {
          timers.splice(index, 1);
        }
      };
    },
    pbkdf2: subtlePbkdf2,
    store,
    policy: {
      idleMs: opts?.idleMs ?? 15 * 60_000,
      maxSessionMs: opts?.maxSessionMs ?? 12 * 3_600_000,
      maxScryptLogN: 20,
    },
  };
  startKernel(platform, port);

  let nextId = 1;
  return {
    posted,
    events,
    store: inner,
    draws,
    call: async (method, params, session) =>
      new Promise<KernelResponse>((resolve) => {
        const id = nextId++;
        pending.set(id, resolve);
        handler?.({ v: 1, id, method, session, params: params ?? null });
      }),
    advance: (ms) => {
      elapsed += ms;
      // Fire due timers in deadline order; a firing timer may re-arm itself (idle reschedule).
      for (;;) {
        const timer = takeDueTimer();
        if (timer === undefined) {
          break;
        }
        timer.fn();
      }
    },
    advanceWall: (ms) => {
      now += ms;
    },
    wallNow: () => now,
    settle: async () => {
      // Store watchers reload the image asynchronously; let them flush.
      await new Promise<void>((resolve) => {
        setTimeout(resolve);
      });
    },
    sendRaw: async (raw) => {
      // The kernel replies with the parsed id only when v and id are both well-formed.
      let expectedId = 0;
      if (typeof raw === "object" && raw !== null && !Array.isArray(raw)) {
        const fields = raw as { v?: unknown; id?: unknown };
        if (
          fields.v === 1 &&
          typeof fields.id === "number" &&
          Number.isSafeInteger(fields.id) &&
          fields.id >= 0
        ) {
          expectedId = fields.id;
        }
      }
      return new Promise<KernelResponse>((resolve) => {
        pending.set(expectedId, resolve);
        handler?.(raw);
      });
    },
  };
}
