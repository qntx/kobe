import { readFileSync } from "node:fs";
import { join } from "node:path";

import { KernelError } from "../src/errors.ts";
import type { KernelErrorCode } from "../src/errors.ts";
import type { Pbkdf2, Random } from "../src/platform.ts";

const VECTORS = join(import.meta.dirname, "../../../vectors");

export function loadVectors(file: string): unknown {
  return JSON.parse(readFileSync(join(VECTORS, file), "utf8"));
}

/** Test-only PBKDF2 over WebCrypto (global in Node ≥ 20 and browsers). */
export const subtlePbkdf2: Pbkdf2 = async (hash, password, salt, iterations, length) => {
  const algorithm = hash === "sha256" ? "SHA-256" : "SHA-512";
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    new Uint8Array(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await globalThis.crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: algorithm, salt: new Uint8Array(salt), iterations },
    key,
    length * 8,
  );
  return new Uint8Array(bits);
};

/** Deterministic Random for vector tests: returns `bytes` (no length check). */
export function fixedRandom(bytes: Uint8Array): Random {
  return () => bytes;
}

/** Runs `fn` and returns the KernelError code it threw, if it did. */
export function kernelError(fn: () => unknown): KernelErrorCode | undefined {
  try {
    fn();
  } catch (error) {
    if (error instanceof KernelError) {
      return error.code;
    }
    throw error;
  }
  return undefined;
}
