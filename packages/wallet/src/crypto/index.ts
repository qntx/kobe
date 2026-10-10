import { hmac } from "@noble/hashes/hmac.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { keccak_256 } from "@noble/hashes/sha3.js";

/** SHA-256 digest. */
export function sha256Bytes(data: Uint8Array): Uint8Array {
  return sha256(data);
}

/** SHA-512 digest. */
export function sha512Bytes(data: Uint8Array): Uint8Array {
  return sha512(data);
}

/** Keccak-256 (Ethereum). */
export function keccak256(data: Uint8Array): Uint8Array {
  return keccak_256(data);
}

/** RIPEMD-160. */
export function ripemd160Bytes(data: Uint8Array): Uint8Array {
  return ripemd160(data);
}

/** HMAC-SHA-512. */
export function hmacSha512(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha512, key, data);
}

/** HMAC-SHA-256. */
export function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha256, key, data);
}

/**
 * PBKDF2-HMAC-SHA-512 (BIP-39 seed).
 * @param password UTF-8 password bytes
 * @param salt UTF-8 salt bytes
 * @param iterations default 2048 for BIP-39
 * @param dkLen default 64 for BIP-39 seed
 */
export function pbkdf2Sha512(
  password: Uint8Array,
  salt: Uint8Array,
  iterations = 2048,
  dkLen = 64,
): Uint8Array {
  return pbkdf2(sha512, password, salt, { c: iterations, dkLen });
}

/** PBKDF2-HMAC-SHA-256 (RFC 8018 / RFC 7914). */
export function pbkdf2Sha256(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  dkLen: number,
): Uint8Array {
  return pbkdf2(sha256, password, salt, { c: iterations, dkLen });
}

/** Double SHA-256 (Bitcoin hash256). */
export function hash256(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}

/** HASH160 = RIPEMD160(SHA256(data)). */
export function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}
