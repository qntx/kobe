import { base58 } from "@scure/base";
import { hash256, keccak256 } from "../../crypto/index.ts";
import { DeriveError } from "../../errors/derive.ts";

/** Base58Check(0x41 || keccak256(uncompressed[1..])[12..]). */
export function tronAddressFromUncompressed(uncompressed: Uint8Array): string {
  if (uncompressed.length !== 65 || uncompressed[0] !== 0x04) {
    throw new DeriveError(
      "crypto",
      "TRON address requires 65-byte uncompressed secp256k1 public key",
    );
  }
  const hash = keccak256(uncompressed.subarray(1));
  const body = new Uint8Array(21);
  body[0] = 0x41;
  body.set(hash.subarray(12), 1);
  const checksum = hash256(body).subarray(0, 4);
  const full = new Uint8Array(25);
  full.set(body, 0);
  full.set(checksum, 21);
  return base58.encode(full);
}

export function tronPath(index: number): string {
  return `m/44'/195'/0'/0/${index}`;
}
