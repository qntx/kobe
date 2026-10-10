import { ed25519 } from "@noble/curves/ed25519.js";
import { SignError } from "../errors/sign.ts";

/** Ed25519 accepts any 32-byte seed. */
export function isValidEd25519Secret(sk: Uint8Array): boolean {
  return sk.length === 32;
}

/**
 * 32-byte public key from 32-byte secret seed.
 * @throws SignError invalid_key
 */
export function ed25519PublicKey(secret: Uint8Array): Uint8Array {
  if (!isValidEd25519Secret(secret)) {
    throw new SignError("invalid_key", "ed25519 secret must be 32 bytes");
  }
  return ed25519.getPublicKey(secret);
}

/**
 * Sign arbitrary message bytes (RFC 8032). Returns 64-byte signature.
 * @throws SignError invalid_key | signing_failed
 */
export function ed25519Sign(secret: Uint8Array, message: Uint8Array): Uint8Array {
  if (!isValidEd25519Secret(secret)) {
    throw new SignError("invalid_key", "ed25519 secret must be 32 bytes");
  }
  try {
    return ed25519.sign(message, secret);
  } catch (e) {
    throw new SignError("signing_failed", e instanceof Error ? e.message : "ed25519 sign failed", {
      cause: e,
    });
  }
}

/**
 * Verify Ed25519 signature. Malformed → throw; reject → false.
 * @throws SignError invalid_signature | invalid_key
 */
export function ed25519Verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (publicKey.length !== 32) {
    throw new SignError("invalid_key", "ed25519 public key must be 32 bytes");
  }
  if (signature.length !== 64) {
    throw new SignError("invalid_signature", "ed25519 signature must be 64 bytes");
  }
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch (e) {
    throw new SignError(
      "invalid_signature",
      e instanceof Error ? e.message : "malformed signature",
      { cause: e },
    );
  }
}
