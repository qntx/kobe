import { gcm } from "@noble/ciphers/aes.js";

import { VaultError } from "../errors/vault.ts";

/** Envelope format version byte (`sealed[0]`, bound into the AAD). */
export const VAULT_VERSION = 1;

const KEY_LEN = 32;
const NONCE_LEN = 12;
/** Version(1) + nonce(12) + tag(16) with an empty ciphertext. */
const SEALED_MIN_LEN = 29;

function checkKey(key: Uint8Array): void {
  if (key.length !== KEY_LEN) {
    throw new VaultError("input", "vault: key must be 32 bytes");
  }
}

function checkContext(context: string): void {
  if (context.length === 0) {
    throw new VaultError("input", "vault: context must not be empty");
  }
}

/** AAD = `[VAULT_VERSION] || UTF-8(context)` — the version byte is bound in. */
function aad(context: string): Uint8Array {
  const utf8 = new TextEncoder().encode(context);
  const out = new Uint8Array(1 + utf8.length);
  out[0] = VAULT_VERSION;
  out.set(utf8, 1);
  return out;
}

/**
 * Seal `plaintext` under `key` with the given `context` (envelope v1).
 *
 * `context` is a non-empty UTF-8 string chosen by the application and bound into the ciphertext as
 * associated data. `rng` fills the 12-byte nonce and defaults to `crypto.getRandomValues`.
 *
 * @throws VaultError input if `key` is not 32 bytes or `context` is empty
 */
export function seal(
  key: Uint8Array,
  plaintext: Uint8Array,
  context: string,
  rng: (bytes: Uint8Array<ArrayBuffer>) => void = (bytes) => crypto.getRandomValues(bytes),
): Uint8Array {
  checkKey(key);
  checkContext(context);

  const nonce = new Uint8Array(NONCE_LEN);
  rng(nonce);
  const ct = gcm(key, nonce, aad(context)).encrypt(plaintext);

  const sealed = new Uint8Array(SEALED_MIN_LEN + plaintext.length);
  sealed[0] = VAULT_VERSION;
  sealed.set(nonce, 1);
  sealed.set(ct, 1 + NONCE_LEN);
  return sealed;
}

/**
 * Open a sealed envelope v1 blob under `key` with the given `context`.
 *
 * Checks, in order: key length, non-empty context, minimum length, version byte, then AEAD open.
 * Returns a caller-owned copy of the plaintext.
 *
 * @throws VaultError input | version | decrypt
 */
export function open(key: Uint8Array, sealed: Uint8Array, context: string): Uint8Array {
  checkKey(key);
  checkContext(context);
  if (sealed.length < SEALED_MIN_LEN) {
    throw new VaultError("input", "vault: sealed data too short");
  }
  const version = sealed[0] ?? 0;
  if (version !== VAULT_VERSION) {
    throw new VaultError("version", "vault: unsupported envelope version");
  }
  try {
    return gcm(key, sealed.slice(1, 1 + NONCE_LEN), aad(context)).decrypt(
      sealed.slice(1 + NONCE_LEN),
    );
  } catch {
    throw new VaultError("decrypt", "vault: decryption failed");
  }
}
