/**
 * The store RPC shared by the worker (`src/worker/store-client.ts`) and the main side
 * (`src/node/store-server.ts`). The vault image travels as plain structured-clone data — it is
 * ciphertext plus public headers only, never decrypted secrets. This file stays platform-neutral:
 * the port shape is injected on both sides.
 */
import { KernelError, VAULT_FORMAT, isRecordKind } from "@qntx/wallet-kernel";
import type { KernelErrorCode, StoreOp, VaultImage } from "@qntx/wallet-kernel";

export type StorePort = {
  readonly post: (message: unknown) => void;
  readonly listen: (handler: (message: unknown) => void) => () => void;
};

export type StoreRequest =
  | { readonly t: "load"; readonly id: number }
  | { readonly t: "commit"; readonly id: number; readonly ops: ReadonlyArray<StoreOp> };

export type StoreReply =
  | { readonly t: "loaded"; readonly id: number; readonly image: WireImage }
  | { readonly t: "committed"; readonly id: number }
  | { readonly t: "failed"; readonly id: number; readonly code: KernelErrorCode }
  | { readonly t: "changed" };

/** Structured clone preserves `undefined` properties, so `meta` travels as-is. */
type WireImage = VaultImage;

export function encodeImage(image: VaultImage): WireImage {
  return { meta: image.meta, factors: image.factors, records: image.records };
}

// Bounds for a vault image read back from an untrusted store (IndexedDB, the Node host's
// RPC replies). The same-origin main thread can write anything into those stores, so the
// kernel never treats loaded rows as trustworthy — every field is checked structurally.
const MAX_ID = 128;
const MAX_HEADER = 4096;
const MIN_SEALED = 16;
const MAX_SEALED = 8192;
const MAX_ROWS = 4096;
const HEX_32 = /^[0-9a-f]{32}$/;

function bad(what: string): KernelError {
  return new KernelError("integrity", `vault store: ${what}`);
}

function plainObject(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw bad("row is not an object");
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) {
    throw bad("row is not a plain object");
  }
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- narrowed to a plain object above
  return value as Record<string, unknown>;
}

function exactKeys(row: Record<string, unknown>, keys: string): void {
  if (Object.keys(row).sort().join(",") !== keys) {
    throw bad("row has unexpected fields");
  }
}

function boundedString(value: unknown, max: number, what: string): void {
  if (typeof value !== "string" || value.length > max) {
    throw bad(`${what} is not a string within ${max} chars`);
  }
}

function safeNonNegative(value: unknown, what: string): void {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw bad(`${what} is not a safe non-negative integer`);
  }
}

function sealedBytes(value: unknown): void {
  if (
    !(value instanceof Uint8Array) ||
    value.byteLength < MIN_SEALED ||
    value.byteLength > MAX_SEALED
  ) {
    throw bad("sealed is not a Uint8Array within sane bounds");
  }
}

/**
 * Strict shape check for a vault image. Returns the input typed as VaultImage; throws KernelError
 * "integrity" on any structural violation so a tampered store fails closed. `meta.format` is
 * checked before anything else: a non-integer is integrity, a different format is "unsupported"
 * (data written by another build — left untouched).
 */
export function assertVaultImage(value: unknown): VaultImage {
  const image = plainObject(value);
  const { meta, records, factors } = image;
  if (meta !== undefined) {
    const metaRow = plainObject(meta);
    const { format } = metaRow;
    if (typeof format !== "number" || !Number.isSafeInteger(format)) {
      throw bad("meta format is not a safe integer");
    }
    if (format !== VAULT_FORMAT) {
      throw new KernelError("unsupported", "vault store: meta format needs a newer build");
    }
    exactKeys(metaRow, "failedAttempts,format,keyId,lastFailureAt,revision");
    if (typeof metaRow["keyId"] !== "string" || !HEX_32.test(metaRow["keyId"])) {
      throw bad("meta keyId is not 32 lowercase hex");
    }
    if (
      typeof metaRow["revision"] !== "number" ||
      !Number.isSafeInteger(metaRow["revision"]) ||
      metaRow["revision"] < 1
    ) {
      throw bad("meta revision is not a safe integer ≥ 1");
    }
    safeNonNegative(metaRow["failedAttempts"], "meta failedAttempts");
    safeNonNegative(metaRow["lastFailureAt"], "meta lastFailureAt");
  }
  if (!Array.isArray(records) || records.length > MAX_ROWS) {
    throw bad("records is not a bounded array");
  }
  for (const entry of records) {
    const row = plainObject(entry);
    exactKeys(row, "header,id,kind,sealed");
    if (typeof row["kind"] !== "string" || !isRecordKind(row["kind"])) {
      throw bad("record kind is not a valid kind string");
    }
    boundedString(row["id"], MAX_ID, "record id");
    boundedString(row["header"], MAX_HEADER, "record header");
    sealedBytes(row["sealed"]);
  }
  if (!Array.isArray(factors) || factors.length > MAX_ROWS) {
    throw bad("factors is not a bounded array");
  }
  for (const entry of factors) {
    const row = plainObject(entry);
    exactKeys(row, "header,id,kind,sealed");
    if (typeof row["kind"] !== "string" || !isRecordKind(row["kind"])) {
      // Structure only — whether this build knows the kind is the kernel's call (unsupported).
      throw bad("factor kind is not a valid kind string");
    }
    if (typeof row["id"] !== "string" || !HEX_32.test(row["id"])) {
      throw bad("factor id is not 32 lowercase hex");
    }
    boundedString(row["header"], MAX_HEADER, "factor header");
    sealedBytes(row["sealed"]);
  }
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- every row field was checked above
  return image as VaultImage;
}

/** The idle-timeout choices a host may request; the worker maps them to milliseconds. */
export type IdleMinutes = 5 | 15 | 60;

export function isIdleMinutes(value: unknown): value is IdleMinutes {
  return value === 5 || value === 15 || value === 60;
}

export function idleMsOf(minutes: IdleMinutes): number {
  return minutes * 60_000;
}

/** The fixed maximum session duration owned by the worker entries (never a host input). */
export const MAX_SESSION_MS: number = 12 * 3_600_000;

/**
 * The first message the Web host posts to `kernel.worker.js`: the session policy. The browser
 * worker's vault lives in IndexedDB inside the worker itself, so unlike Node there is no store port
 * — policy is all the kernel needs before `startKernel` runs.
 */
export type BrowserWorkerInit = {
  readonly t: "init";
  readonly idleMinutes: IdleMinutes;
};

function plainInitObject(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return undefined;
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) {
    return undefined;
  }
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- narrowed to a plain object above
  return value as Record<string, unknown>;
}

/** Strict init-message validation; anything else must not start the kernel. */
export function isBrowserWorkerInit(value: unknown): value is BrowserWorkerInit {
  const init = plainInitObject(value);
  return (
    init !== undefined &&
    Object.keys(init).sort().join(",") === "idleMinutes,t" &&
    init["t"] === "init" &&
    isIdleMinutes(init["idleMinutes"])
  );
}

/**
 * Strict `workerData` validation for the Node kernel worker: `{ idleMinutes, storePort }` and
 * nothing else. `storePort` is checked structurally (the real type lives behind the worker_threads
 * boundary); a wrong shape must not start the kernel.
 */
export function isNodeWorkerData(
  value: unknown,
): value is { readonly idleMinutes: IdleMinutes; readonly storePort: unknown } {
  const data = plainInitObject(value);
  return (
    data !== undefined &&
    Object.keys(data).sort().join(",") === "idleMinutes,storePort" &&
    isIdleMinutes(data["idleMinutes"]) &&
    typeof data["storePort"] === "object" &&
    data["storePort"] !== null
  );
}
