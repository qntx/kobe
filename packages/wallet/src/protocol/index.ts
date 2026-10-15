/**
 * Secret-area wire protocol (design/impl/wallet-e0.mdx "协议与传输"). Shared by the kernel and the main
 * runtime: the kernel validates every request, the host validates every response. Web/Node carry
 * ProtocolValue via structured clone; the RN host encodes the same values as CBOR.
 */
import type { LockReason, StatusPayload, WalletErrorCode } from "../types.ts";

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

export {
  METHODS,
  kernelEvent,
  responseError,
  type MethodName,
  type MethodSpec,
  type ParamsOf,
  type ResultOf,
} from "./methods.ts";
export type {
  CreatedResult,
  Factor,
  KeyResult,
  NostrExportFormat,
  NostrImportInput,
  UnsignedEventInput,
  UnwrapResult,
} from "./methods.ts";
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
