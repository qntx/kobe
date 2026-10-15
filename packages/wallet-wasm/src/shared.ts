/**
 * The store RPC shared by the worker (`src/worker/store-client.ts`) and the main side
 * (`src/node/store-server.ts`). The vault image travels as plain structured-clone data — it is
 * ciphertext plus public headers only, never decrypted secrets. This file stays platform-neutral:
 * the port shape is injected on both sides.
 */
import { KernelError } from "@qntx/wallet-kernel";
import type { StoreOp, VaultImage } from "@qntx/wallet-kernel";

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
const FACTOR_ID = /^[0-9a-f]{32}$/;
const RECORD_KINDS = new Set(["entropy", "nostr-key", "data-key"]);
const FACTOR_KINDS = new Set(["password", "passkey"]);

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
 * "integrity" on any violation so a tampered store fails closed.
 */
export function assertVaultImage(value: unknown): VaultImage {
  const image = plainObject(value);
  const { meta, records, factors } = image;
  if (meta !== undefined) {
    const metaRow = plainObject(meta);
    exactKeys(metaRow, "failedAttempts,format,retryAt");
    if (metaRow["format"] !== 1) {
      throw bad("meta format is not 1");
    }
    safeNonNegative(metaRow["failedAttempts"], "meta failedAttempts");
    safeNonNegative(metaRow["retryAt"], "meta retryAt");
  }
  if (!Array.isArray(records) || records.length > MAX_ROWS) {
    throw bad("records is not a bounded array");
  }
  for (const entry of records) {
    const row = plainObject(entry);
    exactKeys(row, "header,id,kind,sealed");
    if (typeof row["kind"] !== "string" || !RECORD_KINDS.has(row["kind"])) {
      throw bad("record kind is unknown");
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
    if (typeof row["kind"] !== "string" || !FACTOR_KINDS.has(row["kind"])) {
      throw bad("factor kind is unknown");
    }
    if (typeof row["id"] !== "string" || !FACTOR_ID.test(row["id"])) {
      throw bad("factor id is not 32 lowercase hex");
    }
    boundedString(row["header"], MAX_HEADER, "factor header");
    sealedBytes(row["sealed"]);
  }
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- every row field was checked above
  return image as VaultImage;
}

/**
 * The first message the Web host posts to `kernel.worker.js`: the session policy. The browser
 * worker's vault lives in IndexedDB inside the worker itself, so unlike Node there is no store port
 * — policy is all the kernel needs before `startKernel` runs.
 */
export type BrowserWorkerInit = {
  readonly t: "init";
  readonly idleMs: number;
  readonly maxSessionMs: number;
};

/** Strict init-message validation; anything else must not start the kernel. */
export function isBrowserWorkerInit(value: unknown): value is BrowserWorkerInit {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) {
    return false;
  }
  const keys = Object.keys(value).sort();
  if (keys.join(",") !== "idleMs,maxSessionMs,t") {
    return false;
  }
  const init = value as BrowserWorkerInit; // oxlint-disable-line typescript/no-unsafe-type-assertion -- narrowed above
  return (
    init.t === "init" &&
    Number.isSafeInteger(init.idleMs) &&
    init.idleMs > 0 &&
    Number.isSafeInteger(init.maxSessionMs) &&
    init.maxSessionMs > 0
  );
}
