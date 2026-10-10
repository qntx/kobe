import { base58xrp } from "@scure/base";
import { hash160, hash256, sha512Bytes } from "../../crypto/index.ts";
import { DeriveError } from "../../errors/derive.ts";

/** XRPL account address version byte. */
const ACCOUNT_VERSION = 0x00;

/** rippled `HashPrefix::txSign`: ASCII `STX` + NUL. */
export const XRPL_STX_PREFIX = Uint8Array.of(0x53, 0x54, 0x58, 0x00);

export function xrplPath(index: number): string {
  return `m/44'/144'/0'/0/${index}`;
}

/** SHA-512, first 32 bytes. */
export function xrplSha512Half(data: Uint8Array): Uint8Array {
  return sha512Bytes(data).subarray(0, 32);
}

/** SHA-512-half of `STX\0 || tx_bytes`. */
export function xrplTxDigest(txBytes: Uint8Array): Uint8Array {
  const buf = new Uint8Array(XRPL_STX_PREFIX.length + txBytes.length);
  buf.set(XRPL_STX_PREFIX, 0);
  buf.set(txBytes, XRPL_STX_PREFIX.length);
  return xrplSha512Half(buf);
}

/**
 * Classic `r…` address: XRPL base58(`0x00 || HASH160(compressed) || checksum`).
 */
export function xrplAddressFromCompressed(compressed: Uint8Array): string {
  if (compressed.length !== 33 || (compressed[0] !== 0x02 && compressed[0] !== 0x03)) {
    throw new DeriveError("crypto", "xrpl: expected 33-byte compressed secp256k1 public key");
  }
  const accountId = hash160(compressed);
  const payload = new Uint8Array(25);
  payload[0] = ACCOUNT_VERSION;
  payload.set(accountId, 1);
  payload.set(hash256(payload.subarray(0, 21)).subarray(0, 4), 21);
  try {
    return base58xrp.encode(payload);
  } catch (e) {
    throw new DeriveError(
      "address_encoding",
      e instanceof Error ? `xrpl base58: ${e.message}` : "xrpl base58",
      { cause: e },
    );
  }
}
