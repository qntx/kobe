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

/** Session limits chosen by the host (Web and Node: idle from `autoLock`, max 12 h). */
export type KernelPolicy = {
  readonly idleMs: number;
  readonly maxSessionMs: number;
};

/**
 * Schedules `fn` after `delayMs` and returns a cancel function. Injected because bare Hermes has no
 * timer globals; on Web/Node the host passes `setTimeout`/`clearTimeout`.
 */
export type SetTimer = (delayMs: number, fn: () => void) => () => void;

export type KernelPlatform = {
  readonly random: Random;
  /** Milliseconds since the epoch; fake clocks keep tests deterministic. */
  readonly now: () => number;
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
