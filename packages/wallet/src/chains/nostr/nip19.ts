import { bech32 } from "@scure/base";
import { DeriveError } from "../../errors/derive.ts";
import { SignError } from "../../errors/sign.ts";

export const NSEC_HRP = "nsec";
export const NPUB_HRP = "npub";

export function encodeNip19(hrp: string, data: Uint8Array): string {
  return bech32.encode(hrp, bech32.toWords(data));
}

export function decodeNip19(encoded: string, expectedHrp: string): Uint8Array {
  let decoded: { prefix: string; bytes: Uint8Array };
  try {
    decoded = bech32.decodeToBytes(encoded);
  } catch (e) {
    throw new SignError(
      "invalid_key",
      e instanceof Error ? `nip-19 bech32: ${e.message}` : "nip-19 bech32",
      { cause: e },
    );
  }
  if (decoded.prefix !== expectedHrp) {
    throw new SignError(
      "invalid_key",
      `nip-19 bech32: expected HRP \`${expectedHrp}\`, got \`${decoded.prefix}\``,
    );
  }
  if (decoded.bytes.length !== 32) {
    throw new SignError(
      "invalid_key",
      `nip-19 bech32: expected 32 bytes, got ${decoded.bytes.length}`,
    );
  }
  return decoded.bytes;
}

export function encodeNpub(xonly: Uint8Array): string {
  if (xonly.length !== 32) {
    throw new DeriveError("crypto", "nostr: x-only pubkey must be 32 bytes");
  }
  try {
    return encodeNip19(NPUB_HRP, xonly);
  } catch (e) {
    throw new DeriveError(
      "address_encoding",
      e instanceof Error ? `nostr npub: ${e.message}` : "nostr npub encoding",
      { cause: e },
    );
  }
}

export function encodeNsec(secret: Uint8Array): string {
  if (secret.length !== 32) {
    throw new DeriveError("crypto", "nostr: secret must be 32 bytes");
  }
  try {
    return encodeNip19(NSEC_HRP, secret);
  } catch (e) {
    throw new DeriveError(
      "address_encoding",
      e instanceof Error ? `nostr nsec: ${e.message}` : "nostr nsec encoding",
      { cause: e },
    );
  }
}

export function nostrPath(index: number): string {
  return `m/44'/1237'/${index}'/0/0`;
}

export function xonlyFromCompressed(compressed: Uint8Array): Uint8Array {
  if (compressed.length !== 33) {
    throw new DeriveError("crypto", "nostr: compressed pubkey shorter than 33 bytes");
  }
  return compressed.subarray(1);
}
