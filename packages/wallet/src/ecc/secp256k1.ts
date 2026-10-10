import { secp256k1 } from "@noble/curves/secp256k1.js";

import { SignError } from "../errors/sign.ts";

const { ORDER } = secp256k1.Point.Fn;

/** True if `sk` is a valid secp256k1 scalar (not zero, < n). */
export function isValidSecp256k1Secret(sk: Uint8Array): boolean {
  if (sk.length !== 32) {
    return false;
  }
  if (!secp256k1.utils.isValidSecretKey(sk)) {
    return false;
  }
  let n = 0n;
  for (const b of sk) {
    n = (n << 8n) | BigInt(b);
  }
  return n !== 0n && n < ORDER;
}

/**
 * Compressed (33) or uncompressed (65) public key from a 32-byte secret.
 *
 * @throws SignError invalid_key
 */
export function secp256k1PublicKey(secret: Uint8Array, compressed = true): Uint8Array {
  if (!isValidSecp256k1Secret(secret)) {
    throw new SignError("invalid_key", "secp256k1 scalar out of range or wrong length");
  }
  return secp256k1.getPublicKey(secret, compressed);
}

/**
 * ECDSA sign prehash (RFC 6979 via noble). Returns compact 64-byte r||s and recovery 0|1.
 *
 * @throws SignError invalid_key | invalid_message | signing_failed
 */
export function secp256k1SignPrehash(
  secret: Uint8Array,
  digest32: Uint8Array,
): { signature: Uint8Array; recovery: number } {
  if (digest32.length !== 32) {
    throw new SignError("invalid_message", "digest must be 32 bytes");
  }
  if (!isValidSecp256k1Secret(secret)) {
    throw new SignError("invalid_key", "secp256k1 scalar out of range or wrong length");
  }
  try {
    const recovered = secp256k1.sign(digest32, secret, {
      prehash: false,
      format: "recovered",
    });
    if (!(recovered instanceof Uint8Array) || recovered.length !== 65) {
      throw new Error("unexpected recovered signature encoding");
    }
    const [recovery] = recovered;
    if (recovery === undefined) {
      throw new Error("unexpected recovered signature encoding");
    }
    if (recovery !== 0 && recovery !== 1) {
      throw new Error(`unexpected recovery id ${recovery}`);
    }
    return { signature: recovered.subarray(1), recovery };
  } catch (error) {
    if (error instanceof SignError) {
      throw error;
    }
    throw new SignError(
      "signing_failed",
      error instanceof Error ? error.message : "secp256k1 sign failed",
      { cause: error },
    );
  }
}

/**
 * Verify ECDSA prehash. Malformed signature → throw; crypto reject → false.
 *
 * @throws SignError invalid_signature | invalid_message | invalid_key
 */
/**
 * ECDSA sign prehash, ASN.1 DER (typically 70–72 bytes). No recovery id.
 *
 * @throws SignError invalid_key | invalid_message | signing_failed
 */
export function secp256k1SignPrehashDer(secret: Uint8Array, digest32: Uint8Array): Uint8Array {
  if (digest32.length !== 32) {
    throw new SignError("invalid_message", "digest must be 32 bytes");
  }
  if (!isValidSecp256k1Secret(secret)) {
    throw new SignError("invalid_key", "secp256k1 scalar out of range or wrong length");
  }
  try {
    const der = secp256k1.sign(digest32, secret, { prehash: false, format: "der" });
    if (!(der instanceof Uint8Array) || der.length < 8 || der[0] !== 0x30) {
      throw new Error("unexpected DER signature encoding");
    }
    return der;
  } catch (error) {
    if (error instanceof SignError) {
      throw error;
    }
    throw new SignError(
      "signing_failed",
      error instanceof Error ? error.message : "secp256k1 DER sign failed",
      { cause: error },
    );
  }
}

/**
 * Verify DER ECDSA prehash. Malformed DER → throw; crypto reject → false.
 *
 * @throws SignError invalid_signature | invalid_message | invalid_key
 */
export function secp256k1VerifyPrehashDer(
  publicKey: Uint8Array,
  digest32: Uint8Array,
  signatureDer: Uint8Array,
): boolean {
  if (digest32.length !== 32) {
    throw new SignError("invalid_message", "digest must be 32 bytes");
  }
  if (publicKey.length !== 33 && publicKey.length !== 65) {
    throw new SignError("invalid_key", "public key must be 33 or 65 bytes");
  }
  let compact: Uint8Array;
  try {
    compact = secp256k1.Signature.fromBytes(signatureDer, "der").toBytes("compact");
  } catch (error) {
    throw new SignError(
      "invalid_signature",
      error instanceof Error ? error.message : "malformed DER signature",
      { cause: error },
    );
  }
  return secp256k1VerifyPrehash(publicKey, digest32, compact);
}

export function secp256k1VerifyPrehash(
  publicKey: Uint8Array,
  digest32: Uint8Array,
  signature64: Uint8Array,
): boolean {
  if (digest32.length !== 32) {
    throw new SignError("invalid_message", "digest must be 32 bytes");
  }
  if (signature64.length !== 64) {
    throw new SignError("invalid_signature", "signature must be 64 bytes compact r||s");
  }
  if (publicKey.length !== 33 && publicKey.length !== 65) {
    throw new SignError("invalid_key", "public key must be 33 or 65 bytes");
  }
  try {
    return secp256k1.verify(signature64, digest32, publicKey, {
      prehash: false,
    });
  } catch (error) {
    throw new SignError(
      "invalid_signature",
      error instanceof Error ? error.message : "malformed signature",
      { cause: error },
    );
  }
}
