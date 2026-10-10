import { base58 } from "@scure/base";

import { hash256 } from "../../crypto/index.ts";

/** Base58Check(version || payload). */
export function base58check(version: number, payload: Uint8Array): string {
  const body = new Uint8Array(1 + payload.length);
  body[0] = version;
  body.set(payload, 1);
  return base58checkEncode(body);
}

export function base58checkEncode(body: Uint8Array): string {
  const checksum = hash256(body).subarray(0, 4);
  const full = new Uint8Array(body.length + 4);
  full.set(body, 0);
  full.set(checksum, body.length);
  return base58.encode(full);
}
