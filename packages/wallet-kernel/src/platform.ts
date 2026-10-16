/**
 * Platform capabilities injected by the host packages. The kernel holds no ambient singletons and
 * imports no platform APIs; every capability arrives through these types.
 */
import type { ProtocolValue } from "@qntx/wallet/protocol";

import type { RecordStore } from "./vault/store.ts";

/** Returns `length` cryptographically random bytes. */
export type Random = (length: number) => Uint8Array;

export type Pbkdf2 = (
  hash: "sha256" | "sha512",
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  length: number,
) => Promise<Uint8Array>;

/** Session limits owned by the worker entry (Web and Node: idle 5/15/60 min, max 12 h). */
export type KernelPolicy = {
  readonly idleMs: number;
  readonly maxSessionMs: number;
  /** Upper bound for ncryptsec imports; enforced by the nostr module. */
  readonly maxScryptLogN: number;
  /**
   * What refreshes the idle timer: "presence" counts only user-presence-bearing methods (web —
   * background traffic must not hold a session open); "request" counts every successful request
   * (node — there is no human user to observe).
   */
  readonly activity: "presence" | "request";
};

/**
 * Schedules `fn` after `delayMs` and returns a cancel function. Injected because bare Hermes has no
 * timer globals; on Web/Node the host passes `setTimeout`/`clearTimeout`.
 */
export type SetTimer = (delayMs: number, fn: () => void) => () => void;

export type KernelPlatform = {
  readonly random: Random;
  /** Milliseconds since the epoch, for persisted timestamps only (createdAt, lastFailureAt). */
  readonly now: () => number;
  /**
   * Monotonic elapsed milliseconds (Web/Node: `performance.now()`); session deadlines are measured
   * on this clock so a wall-clock jump can never extend or shorten a session.
   */
  readonly elapsed: () => number;
  readonly setTimer: SetTimer;
  readonly pbkdf2: Pbkdf2;
  readonly store: RecordStore;
  readonly policy: KernelPolicy;
};

/**
 * One direction of the host↔kernel channel. `post` may move the listed ArrayBuffers (transferable
 * secret bytes); `listen` returns an unsubscribe function. The RN host encodes ProtocolValue as
 * CBOR; Web/Node pass it through structured clone.
 */
export type Port = {
  readonly post: (message: ProtocolValue, transfer: ArrayBuffer[]) => void;
  readonly listen: (handler: (message: unknown) => void) => () => void;
};
