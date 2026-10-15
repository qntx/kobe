import { base64urlnopad } from "@scure/base";

import { KernelError } from "../errors.ts";

/**
 * The strict-JSON helpers every vault header parser shares. Public headers are stored as raw JSON
 * text and enter the envelope AAD verbatim, so encoders fix the key order and parsers are strict:
 * exact key set, exact types and ranges; anything else is `integrity`.
 */

export function headerFailure(): KernelError {
  return new KernelError("integrity", "invalid vault header");
}

export function headerObject(text: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    throw headerFailure();
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw headerFailure();
  }
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- narrowed to a non-array object above
  return value as Record<string, unknown>;
}

/** Exact key set: every expected key present, nothing else. */
export function expectKeys(object: Record<string, unknown>, keys: ReadonlyArray<string>): void {
  const actual = Object.keys(object);
  if (actual.length !== keys.length || !keys.every((key) => Object.hasOwn(object, key))) {
    throw headerFailure();
  }
}

export function asWalletId(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9a-f]{16}$/.test(value)) {
    throw headerFailure();
  }
  return value;
}

export function asPublicKey(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    throw headerFailure();
  }
  return value;
}

export function asGroupIndex(value: unknown): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > 0x7fffffff
  ) {
    throw headerFailure();
  }
  return value;
}

export function asBoolean(value: unknown): boolean {
  if (typeof value !== "boolean") {
    throw headerFailure();
  }
  return value;
}

export function asCreatedAt(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw headerFailure();
  }
  return value;
}

/** Canonical unpadded base64url that decodes to `min`–`max` bytes. */
export function asBase64url(value: unknown, min: number, max: number): string {
  if (typeof value !== "string") {
    throw headerFailure();
  }
  let decoded: Uint8Array;
  try {
    decoded = base64urlnopad.decode(value);
  } catch {
    throw headerFailure();
  }
  if (decoded.length < min || decoded.length > max || base64urlnopad.encode(decoded) !== value) {
    throw headerFailure();
  }
  return value;
}
