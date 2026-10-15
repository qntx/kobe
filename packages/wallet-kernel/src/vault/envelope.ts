import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";

import { KernelError } from "../errors.ts";
import type { Random } from "../platform.ts";

/**
 * Envelope v1:
 *
 * Sealed = 0x01 ‖ nonce(24) ‖ XChaCha20-Poly1305(key, nonce, plaintext, aad)
 *
 * Aad = 0x01 ‖ u16be(byteLength(UTF-8(context))) ‖ UTF-8(context) ‖ UTF-8(header)
 *
 * The header is the raw stored JSON text, so public headers are authenticated exactly as stored (no
 * canonicalization step).
 */
const VERSION = 0x01;

export function recordContext(kind: string, id: string): string {
  return `qntx-wallet/vault/v1/record/${kind}/${id}`;
}

export function factorContext(kind: string, id: string): string {
  return `qntx-wallet/vault/v1/factor/${kind}/${id}`;
}

export function aadOf(context: string, header: string): Uint8Array {
  const contextBytes = utf8ToBytes(context);
  const headerBytes = utf8ToBytes(header);
  const aad = new Uint8Array(3 + contextBytes.length + headerBytes.length);
  aad[0] = VERSION;
  new DataView(aad.buffer, aad.byteOffset, aad.byteLength).setUint16(1, contextBytes.length);
  aad.set(contextBytes, 3);
  aad.set(headerBytes, 3 + contextBytes.length);
  return aad;
}

export function seal(
  key: Uint8Array,
  plaintext: Uint8Array,
  context: string,
  header: string,
  random: Random,
): Uint8Array {
  if (key.length !== 32) {
    throw new KernelError("invalid-input", "envelope key must be 32 bytes");
  }
  const nonce = random(24);
  if (nonce.length !== 24) {
    throw new KernelError("integrity", "random source returned a wrong-length nonce");
  }
  const ciphertext = xchacha20poly1305(key, nonce, aadOf(context, header)).encrypt(plaintext);
  return concatBytes(new Uint8Array([VERSION]), nonce, ciphertext);
}

export function open(
  key: Uint8Array,
  sealed: Uint8Array,
  context: string,
  header: string,
): Uint8Array {
  const failure = new KernelError("integrity", "envelope authentication failed");
  if (key.length !== 32 || sealed.length < 1 + 24 + 16 || sealed[0] !== VERSION) {
    throw failure;
  }
  try {
    return xchacha20poly1305(key, sealed.subarray(1, 25), aadOf(context, header)).decrypt(
      sealed.subarray(25),
    );
  } catch {
    throw failure;
  }
}
