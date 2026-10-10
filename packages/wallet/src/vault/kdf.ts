import { hkdf } from "@noble/hashes/hkdf.js";
import { pbkdf2Async } from "@noble/hashes/pbkdf2.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { VaultError } from "../errors/vault.ts";
import { wipeBytes } from "../secret/dispose.ts";

/** Recommended PBKDF2-HMAC-SHA256 iteration count for {@link derivePasswordKey}. */
export const PASSWORD_ITERATIONS = 600_000;

const KEY_LEN = 32;
const MIN_SALT_LEN = 16;
const MAX_PASSWORD_ITERATIONS = 10_000_000;

/**
 * Injected PBKDF2-SHA256 implementation. Defaults to noble's `pbkdf2Async`; inject WebCrypto where
 * it is available — there is no auto-detection.
 */
export type Pbkdf2Sha256 = (
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  length: number,
) => Promise<Uint8Array>;

const noblePbkdf2: Pbkdf2Sha256 = async (password, salt, iterations, length) =>
  pbkdf2Async(sha256, password, salt, { c: iterations, dkLen: length });

/**
 * Derive a 32-byte key from `password` via PBKDF2-HMAC-SHA256 over `UTF-8(NFKC(password))`.
 *
 * @throws VaultError input if the password is empty after NFKC normalization, `salt` is shorter
 *   than 16 bytes, or `iterations` is not an integer in `1..=10_000_000`.
 */
export async function derivePasswordKey(
  password: string,
  salt: Uint8Array,
  iterations: number,
  pbkdf2: Pbkdf2Sha256 = noblePbkdf2,
): Promise<Uint8Array> {
  const normalized = password.normalize("NFKC");
  if (normalized.length === 0) {
    throw new VaultError("input", "vault: password must not be empty");
  }
  if (salt.length < MIN_SALT_LEN) {
    throw new VaultError("input", "vault: salt must be at least 16 bytes");
  }
  if (!Number.isInteger(iterations) || iterations < 1 || iterations > MAX_PASSWORD_ITERATIONS) {
    throw new VaultError("input", "vault: iterations must be an integer in 1..=10000000");
  }

  const passwordBytes = new TextEncoder().encode(normalized);
  try {
    return await pbkdf2(passwordBytes, salt, iterations, KEY_LEN);
  } finally {
    wipeBytes(passwordBytes);
  }
}

/**
 * Derive a 32-byte key from a PRF output (e.g. WebAuthn `prf`) via HKDF-SHA256 (RFC 5869) with an
 * empty salt and `info = UTF-8(info)`.
 *
 * @throws VaultError input if `prfOutput` is not exactly 32 bytes or `info`
 * is empty.
 */
export function derivePrfKey(prfOutput: Uint8Array, info: string): Uint8Array {
  if (prfOutput.length !== KEY_LEN) {
    throw new VaultError("input", "vault: PRF output must be 32 bytes");
  }
  if (info.length === 0) {
    throw new VaultError("input", "vault: info must not be empty");
  }
  return hkdf(sha256, prfOutput, new Uint8Array(0), new TextEncoder().encode(info), KEY_LEN);
}
