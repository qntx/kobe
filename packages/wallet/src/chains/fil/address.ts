import { blake2b } from "@noble/hashes/blake2.js";
import { base32nopad } from "@scure/base";
import { DeriveError } from "../../errors/derive.ts";

/** RFC 4648 base32 lowercase, no padding (Filecoin address alphabet). */
export function filBase32Encode(data: Uint8Array): string {
  try {
    return base32nopad.encode(data).toLowerCase();
  } catch (e) {
    throw new DeriveError(
      "address_encoding",
      e instanceof Error ? `filecoin base32: ${e.message}` : "filecoin base32",
      { cause: e },
    );
  }
}

function blake2bVar(data: Uint8Array, dkLen: number): Uint8Array {
  return blake2b(data, { dkLen });
}

/**
 * Protocol-1 (`f1`) address: BLAKE2b-160(uncompressed) +
 * BLAKE2b-32(0x01 || payload), base32-lower, prefixed `f1`.
 */
export function filAddressFromUncompressed(uncompressed: Uint8Array): string {
  if (uncompressed.length !== 65 || uncompressed[0] !== 0x04) {
    throw new DeriveError(
      "crypto",
      "filecoin f1 address requires 65-byte uncompressed secp256k1 public key",
    );
  }
  const payload = blake2bVar(uncompressed, 20);
  const checksumInput = new Uint8Array(1 + payload.length);
  checksumInput[0] = 0x01;
  checksumInput.set(payload, 1);
  const checksum = blake2bVar(checksumInput, 4);
  const addrBytes = new Uint8Array(payload.length + checksum.length);
  addrBytes.set(payload, 0);
  addrBytes.set(checksum, payload.length);
  return `f1${filBase32Encode(addrBytes)}`;
}

export function filPath(index: number): string {
  return `m/44'/461'/0'/0/${index}`;
}

/** BLAKE2b-256 (Filecoin transaction prehash). */
export function filBlake2b256(data: Uint8Array): Uint8Array {
  return blake2bVar(data, 32);
}
