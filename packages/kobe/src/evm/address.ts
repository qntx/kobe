import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import { KobeError } from "../core/error.ts";

/**
 * EIP-55 checksum address from a 20-byte payload.
 *
 * @throws KobeError input if `address` is not 20 bytes
 */
export function toChecksum(address: Uint8Array): string {
  if (address.length !== 20) {
    throw new KobeError("input", `address must be 20 bytes, got ${address.length}`);
  }
  const hex = bytesToHex(address);
  const hash = keccak_256(new TextEncoder().encode(hex));
  let out = "0x";
  for (const [i, byte] of hash.subarray(0, 20).entries()) {
    const hi = hex.charAt(2 * i);
    const lo = hex.charAt(2 * i + 1);
    out += Math.floor(byte / 16) >= 8 ? hi.toUpperCase() : hi;
    out += byte % 16 >= 8 ? lo.toUpperCase() : lo;
  }
  return out;
}

/**
 * Parse an Ethereum address string into 20 bytes.
 *
 * Accepts `"0x"` + 40 hex characters. Mixed-case input must match the EIP-55 checksum;
 * all-lowercase and all-uppercase input is accepted without a checksum.
 *
 * @throws KobeError input on bad length, missing `0x`, non-hex characters or a checksum mismatch
 */
export function parseAddress(address: string): Uint8Array {
  if (!address.startsWith("0x")) {
    throw new KobeError("input", "address must start with 0x");
  }
  const hexPart = address.slice(2);
  if (hexPart.length !== 40) {
    throw new KobeError("input", "address must be 40 hex characters");
  }
  let out: Uint8Array;
  try {
    out = hexToBytes(hexPart);
  } catch {
    throw new KobeError("input", "address contains non-hex characters");
  }
  const hasLower = /[a-f]/.test(hexPart);
  const hasUpper = /[A-F]/.test(hexPart);
  if (hasLower && hasUpper && toChecksum(out) !== address) {
    throw new KobeError("input", "EIP-55 checksum mismatch");
  }
  return out;
}

/**
 * EIP-55 address from an uncompressed secp256k1 public key (65 bytes, `0x04` prefix):
 * `keccak256(uncompressed[1..])[12..]`.
 *
 * @throws KobeError crypto if the key is not 65 bytes with a `0x04` prefix
 */
export function addressFromUncompressed(uncompressed: Uint8Array): string {
  const [prefix] = uncompressed;
  if (uncompressed.length !== 65 || prefix !== 0x04) {
    throw new KobeError("crypto", "EVM address requires 65-byte uncompressed secp256k1 public key");
  }
  return toChecksum(keccak_256(uncompressed.subarray(1)).subarray(12));
}
