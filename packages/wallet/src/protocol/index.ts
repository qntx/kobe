/**
 * Secret-area wire protocol (design/impl/wallet-e0.mdx "协议与传输"). Shared by the kernel and the main
 * runtime: the kernel validates every request, the host validates every response. Web/Node carry
 * ProtocolValue via structured clone; the RN host encodes the same values as CBOR.
 *
 * This file is the method-table composition point: `METHODS` spreads the core table
 * (protocol/core.ts) and the nostr module's table (protocol/nostr.ts), and the status result
 * validator composes the core sections with each module's status section.
 */
import type { LockReason, StatusPayload, WalletErrorCode } from "../types.ts";
// oxlint-disable-next-line unicorn/prefer-export-from -- the tables are composed locally AND re-exported
import {
  CORE_METHODS,
  factorInfo,
  MAX_SNAPSHOT_ITEMS,
  safeTime,
  walletErrorCode,
  walletInfo,
} from "./core.ts";
import type { MethodSpec } from "./core.ts";
// oxlint-disable-next-line unicorn/prefer-export-from -- the table is composed locally AND re-exported
import { NOSTR_METHODS, nostrStatus } from "./nostr.ts";
import { arr, literal, nullValue, obj, opt, union } from "./validate.ts";
import type { Validator } from "./validate.ts";

export type { WalletErrorCode } from "../types.ts";

export const PROTOCOL_VERSION = 1;

/**
 * Responses to requests whose `id` cannot be parsed (malformed envelope) carry id 0. Main-side
 * request ids start at 1, so a `0` is never a real pending request.
 */
export const UNATTRIBUTED_ID = 0;

// oxlint-disable-next-line typescript/no-restricted-types -- JSON null is a protocol value
export type NullValue = null;

export type ProtocolValue =
  | NullValue
  | boolean
  | number // safe integer
  | string
  | Uint8Array
  | ReadonlyArray<ProtocolValue>
  | { readonly [key: string]: ProtocolValue };

export type Request = {
  readonly v: 1;
  readonly id: number;
  readonly method: string;
  readonly session?: string;
  readonly params: ProtocolValue;
};

export type ErrorPayload = {
  readonly code: WalletErrorCode;
  readonly retryAt?: number; // only for "rate-limited"
};

export type Response =
  | { readonly v: 1; readonly id: number; readonly ok: ProtocolValue }
  | { readonly v: 1; readonly id: number; readonly err: ErrorPayload };

export type KernelEvent =
  | { readonly v: 1; readonly event: "status"; readonly status: StatusPayload }
  | { readonly v: 1; readonly event: "locked"; readonly reason: LockReason };

/**
 * The worst-case encoded size of one request, enforced by both sides: the host refuses to post a
 * request over the cap and the kernel answers an oversized raw request with `invalid-input`.
 * Responses are not capped.
 */
export const MAX_REQUEST_BYTES = 1_048_576;

/**
 * Upper-bound byte weight of a protocol value: a string costs `length * 3` (worst-case UTF-8), a
 * Uint8Array its `byteLength`, every scalar and every array element 8, and every object key
 * `key.length * 3 + 8` plus its value. Iterative — a deeply nested value cannot overflow the
 * stack.
 */
export function requestBytes(value: ProtocolValue): number {
  let total = 0;
  const stack: ProtocolValue[] = [value];
  while (stack.length > 0) {
    const item = stack.pop();
    if (item === undefined) {
      continue;
    }
    if (typeof item === "string") {
      total += item.length * 3;
    } else if (item instanceof Uint8Array) {
      total += item.byteLength;
    } else if (item === null || typeof item === "boolean" || typeof item === "number") {
      total += 8;
    } else if (Array.isArray(item)) {
      // Array.isArray widens the readonly member to any[] — re-annotate the element domain.
      const elements: ReadonlyArray<ProtocolValue> = item;
      total += elements.length * 8;
      for (const element of elements) {
        stack.push(element);
      }
    } else {
      for (const [key, child] of Object.entries(item)) {
        total += key.length * 3 + 8;
        stack.push(child);
      }
    }
  }
  return total;
}

/** Deep check that a structured-cloned value is a strict ProtocolValue (no cycles detected). */
export function isProtocolValue(value: unknown): value is ProtocolValue {
  switch (typeof value) {
    case "boolean":
    case "string":
      return true;
    case "number":
      return Number.isSafeInteger(value);
    case "object":
      break;
    default:
      return false;
  }
  if (value === null || value instanceof Uint8Array) {
    return true;
  }
  if (Array.isArray(value)) {
    return value.every(isProtocolValue);
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) {
    return false;
  }
  return Object.values(value).every(isProtocolValue);
}

/** The status payload: core sections plus one object section per protocol module. */
const statusPayload: Validator<StatusPayload> = obj({
  protocol: literal(1),
  vault: union(
    literal("uninitialized"),
    literal("locked"),
    literal("unlocked"),
    literal("corrupted"),
    literal("unsupported"),
    literal("unavailable"),
  ),
  factors: arr(factorInfo, MAX_SNAPSHOT_ITEMS),
  wallets: arr(walletInfo, MAX_SNAPSHOT_ITEMS),
  nostr: nostrStatus,
});

// The explicit annotation is the composition contract: a key missing from either table fails
// declaration emit, and a duplicated key fails assignability (the spread's type for that key
// cannot satisfy the intersection).
export const METHODS: {
  readonly status: MethodSpec<NullValue, StatusPayload>;
} & typeof CORE_METHODS &
  typeof NOSTR_METHODS = {
  status: {
    session: false,
    presence: false,
    params: nullValue,
    result: statusPayload,
  },
  ...CORE_METHODS,
  ...NOSTR_METHODS,
};

// A method name must live in exactly one table: an overlap violates the never constraint.
type AssertNever<T extends never> = T;
export type MethodTablesDisjoint = AssertNever<
  keyof typeof CORE_METHODS & keyof typeof NOSTR_METHODS
>;

export type MethodName = keyof typeof METHODS;
export type ParamsOf<M extends MethodName> = ReturnType<(typeof METHODS)[M]["params"]>;
export type ResultOf<M extends MethodName> = ReturnType<(typeof METHODS)[M]["result"]>;

const lockReason: Validator<LockReason> = union(
  literal("cold-start"),
  literal("user"),
  literal("idle"),
  literal("background"),
  literal("expired"),
  literal("crashed"),
  literal("invalidated"),
);

const errorPayload = obj({ code: walletErrorCode, retryAt: opt(safeTime) });

/** Host-side validators: `kernelEvent` covers the two push messages. */
export const kernelEvent: Validator<KernelEvent> = union(
  obj({ v: literal(1), event: literal("status"), status: statusPayload }),
  obj({ v: literal(1), event: literal("locked"), reason: lockReason }),
);

/** Validates the `err` payload of a response; `ok` is checked against `METHODS[m].result`. */
export const responseError: Validator<{ code: WalletErrorCode; retryAt?: number | undefined }> =
  errorPayload;

export { CORE_METHODS, NOSTR_METHODS, walletErrorCode };
export type { MethodSpec } from "./core.ts";
export type { CreatedResult, Factor } from "./core.ts";
export type {
  KeyResult,
  NostrExportFormat,
  NostrImportInput,
  Rumor,
  SignedEvent,
  UnsignedEventInput,
  UnwrapResult,
} from "./nostr.ts";
export {
  ValidationError,
  arr,
  bool,
  bytes,
  int,
  literal,
  nullValue,
  obj,
  opt,
  str,
  union,
  validate,
  type Validator,
} from "./validate.ts";
