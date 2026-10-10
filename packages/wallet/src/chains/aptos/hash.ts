import { sha3_256 } from "@noble/hashes/sha3.js";
import { bytesToHex } from "../../crypto/hex.ts";

export const APTOS_ED25519_SCHEME = 0x00;
export const APTOS_RAW_TX_DOMAIN = new TextEncoder().encode("APTOS::RawTransaction");

export function sha3_256Bytes(data: Uint8Array): Uint8Array {
  return sha3_256(data);
}

export function aptosRawTxDomainHash(): Uint8Array {
  return sha3_256Bytes(APTOS_RAW_TX_DOMAIN);
}

/** `SHA3-256("APTOS::RawTransaction") || bcs_raw_tx` */
export function aptosTxSigningMessage(bcsRawTx: Uint8Array): Uint8Array {
  const prefix = aptosRawTxDomainHash();
  const out = new Uint8Array(prefix.length + bcsRawTx.length);
  out.set(prefix, 0);
  out.set(bcsRawTx, prefix.length);
  return out;
}

/** Address = `0x` + hex(SHA3-256(pubkey || 0x00)). */
export function aptosAddressFromPublicKey(publicKey: Uint8Array): string {
  const buf = new Uint8Array(33);
  buf.set(publicKey.subarray(0, 32), 0);
  buf[32] = APTOS_ED25519_SCHEME;
  return `0x${bytesToHex(sha3_256Bytes(buf))}`;
}

export function aptosPath(index: number): string {
  return `m/44'/637'/${index}'/0'/0'`;
}
