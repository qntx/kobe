import { bytesToHex, hexToBytes } from "../../crypto/hex.ts";
import { keccak256 } from "../../crypto/index.ts";
import { DeriveError } from "../../errors/derive.ts";

/**
 * EIP-55 checksummed address from a 20-byte payload.
 *
 * @throws DeriveError input if `address` is not 20 bytes
 */
export function toEip55(address: Uint8Array): string {
  if (address.length !== 20) {
    throw new DeriveError("input", `address must be 20 bytes, got ${address.length}`);
  }
  const hex = bytesToHex(address);
  const hash = keccak256(new TextEncoder().encode(hex));
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
 * @throws DeriveError input on bad length, missing `0x` or non-hex characters; address_encoding on
 *   a checksum mismatch
 */
export function parseEvmAddress(address: string): Uint8Array {
  if (!address.startsWith("0x")) {
    throw new DeriveError("input", "address must start with 0x");
  }
  const hexPart = address.slice(2);
  if (hexPart.length !== 40) {
    throw new DeriveError("input", "address must be 40 hex characters");
  }
  let out: Uint8Array;
  try {
    out = hexToBytes(hexPart);
  } catch {
    throw new DeriveError("input", "address contains non-hex characters");
  }
  const hasLower = /[a-f]/.test(hexPart);
  const hasUpper = /[A-F]/.test(hexPart);
  if (hasLower && hasUpper && toEip55(out) !== address) {
    throw new DeriveError("address_encoding", "EIP-55 checksum mismatch");
  }
  return out;
}

/**
 * EIP-55 address from an uncompressed secp256k1 public key (65 bytes, `0x04` prefix):
 * `keccak256(uncompressed[1..])[12..]`.
 *
 * @throws DeriveError crypto if the key is not 65 bytes with a `0x04` prefix
 */
export function evmAddressFromUncompressed(uncompressed: Uint8Array): string {
  const [prefix] = uncompressed;
  if (uncompressed.length !== 65 || prefix !== 0x04) {
    throw new DeriveError(
      "crypto",
      `EVM address requires 65-byte uncompressed secp256k1 public key, got ${uncompressed.length}`,
    );
  }
  return toEip55(keccak256(uncompressed.subarray(1)).subarray(12));
}
