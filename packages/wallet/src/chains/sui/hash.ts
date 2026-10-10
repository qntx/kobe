import { blake2b } from "@noble/hashes/blake2.js";
import { bytesToHex } from "../../crypto/hex.ts";

export const SUI_ED25519_FLAG = 0x00;
export const SUI_TX_INTENT = Uint8Array.of(0x00, 0x00, 0x00);
export const SUI_MSG_INTENT = Uint8Array.of(0x03, 0x00, 0x00);

export function blake2b256(data: Uint8Array): Uint8Array {
  return blake2b(data, { dkLen: 32 });
}

export function suiIntentHash(intent: Uint8Array, data: Uint8Array): Uint8Array {
  const buf = new Uint8Array(intent.length + data.length);
  buf.set(intent, 0);
  buf.set(data, intent.length);
  return blake2b256(buf);
}

/** BCS `vector<u8>`: ULEB128 length + bytes. */
export function bcsSerializeBytes(data: Uint8Array): Uint8Array {
  const lenBytes: number[] = [];
  let len = data.length;
  do {
    let byte = len & 0x7f;
    len >>= 7;
    if (len > 0) byte |= 0x80;
    lenBytes.push(byte);
  } while (len > 0);
  const out = new Uint8Array(lenBytes.length + data.length);
  out.set(lenBytes, 0);
  out.set(data, lenBytes.length);
  return out;
}

export function suiAddressFromPublicKey(publicKey: Uint8Array): string {
  const buf = new Uint8Array(1 + publicKey.length);
  buf[0] = SUI_ED25519_FLAG;
  buf.set(publicKey, 1);
  return `0x${bytesToHex(blake2b256(buf))}`;
}

export function suiPath(index: number): string {
  return `m/44'/784'/${index}'/0'/0'`;
}
