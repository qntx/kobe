import { bytesToHex } from "../../crypto/hex.ts";
import { keccak256 } from "../../crypto/index.ts";
import { DeriveError } from "../../errors/derive.ts";

/** EIP-55 checksum address from a 20-byte payload. */
export function toEip55(addr20: Uint8Array): string {
  if (addr20.length !== 20) {
    throw new DeriveError("address_encoding", `address must be 20 bytes, got ${addr20.length}`);
  }
  const hex = bytesToHex(addr20);
  const hash = keccak256(new TextEncoder().encode(hex));
  let out = "0x";
  for (let i = 0; i < 40; i++) {
    const c = hex[i]!;
    const byte = hash[i >> 1]!;
    const nibble = i % 2 === 0 ? byte >> 4 : byte & 0xf;
    out += nibble >= 8 ? c.toUpperCase() : c;
  }
  return out;
}

/**
 * EIP-55 address from uncompressed secp256k1 pubkey (65 bytes, 0x04 prefix).
 * keccak256(uncompressed[1..]) last 20 bytes.
 */
export function evmAddressFromUncompressed(uncompressed: Uint8Array): string {
  if (uncompressed.length !== 65 || uncompressed[0] !== 0x04) {
    throw new DeriveError(
      "crypto",
      "EVM address requires 65-byte uncompressed secp256k1 public key",
    );
  }
  const hash = keccak256(uncompressed.subarray(1));
  return toEip55(hash.subarray(12));
}
