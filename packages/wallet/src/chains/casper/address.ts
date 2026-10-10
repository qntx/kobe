import { blake2b } from "@noble/hashes/blake2.js";
import { bytesToHex } from "../../crypto/hex.ts";
import { DeriveError } from "../../errors/derive.ts";

export const ACCOUNT_HASH_PREFIX = "account-hash-";
export const ED25519_TAG = 0x01;
export const SECP256K1_TAG = 0x02;

const ED25519_NAME = new TextEncoder().encode("ed25519");
const SECP256K1_NAME = new TextEncoder().encode("secp256k1");

export function formatAccountHash(digest: Uint8Array): string {
  if (digest.length !== 32) {
    throw new DeriveError("crypto", `casper account hash must be 32 bytes, got ${digest.length}`);
  }
  return `${ACCOUNT_HASH_PREFIX}${bytesToHex(digest)}`;
}

export function taggedPublicKeyHex(tag: number, rawKey: Uint8Array): string {
  const buf = new Uint8Array(1 + rawKey.length);
  buf[0] = tag;
  buf.set(rawKey, 1);
  return bytesToHex(buf);
}

function accountHashFromParts(algorithmName: Uint8Array, rawKey: Uint8Array): Uint8Array {
  const preimage = new Uint8Array(algorithmName.length + 1 + rawKey.length);
  preimage.set(algorithmName, 0);
  preimage[algorithmName.length] = 0;
  preimage.set(rawKey, algorithmName.length + 1);
  return blake2b(preimage, { dkLen: 32 });
}

/** Preimage: `b"ed25519" || 0x00 || pubkey`. */
export function accountHashEd25519(pubkey: Uint8Array): Uint8Array {
  if (pubkey.length !== 32) {
    throw new DeriveError(
      "crypto",
      `casper ed25519 public key must be 32 bytes, got ${pubkey.length}`,
    );
  }
  return accountHashFromParts(ED25519_NAME, pubkey);
}

/** Preimage: `b"secp256k1" || 0x00 || compressed`. */
export function accountHashSecp256k1(compressed: Uint8Array): Uint8Array {
  if (compressed.length !== 33 || (compressed[0] !== 0x02 && compressed[0] !== 0x03)) {
    throw new DeriveError("crypto", "casper secp256k1 public key must be 33-byte compressed");
  }
  return accountHashFromParts(SECP256K1_NAME, compressed);
}

export function casperAddressEd25519(pubkey: Uint8Array): string {
  return formatAccountHash(accountHashEd25519(pubkey));
}

export function casperAddressSecp256k1(compressed: Uint8Array): string {
  return formatAccountHash(accountHashSecp256k1(compressed));
}
