import { bech32 } from "@scure/base";

import { KobeError } from "../core/error.ts";

export const NSEC_HRP = "nsec";
export const NPUB_HRP = "npub";

function encodeNip19(hrp: string, data: Uint8Array): string {
  return bech32.encode(hrp, bech32.toWords(data));
}

/** NIP-19 `npub1…` bech32 encoding of a 32-byte x-only public key. */
export function encodeNpub(xonly: Uint8Array): string {
  if (xonly.length !== 32) {
    throw new KobeError("crypto", "nostr: x-only pubkey must be 32 bytes");
  }
  try {
    return encodeNip19(NPUB_HRP, xonly);
  } catch (error) {
    throw new KobeError(
      "address-encoding",
      error instanceof Error ? `nostr npub: ${error.message}` : "nostr npub encoding",
      { cause: error },
    );
  }
}

/** NIP-19 `nsec1…` bech32 encoding of a 32-byte secret key. */
export function encodeNsec(secret: Uint8Array): string {
  if (secret.length !== 32) {
    throw new KobeError("crypto", "nostr: secret must be 32 bytes");
  }
  try {
    return encodeNip19(NSEC_HRP, secret);
  } catch (error) {
    throw new KobeError(
      "address-encoding",
      error instanceof Error ? `nostr nsec: ${error.message}` : "nostr nsec encoding",
      { cause: error },
    );
  }
}

/** NIP-06 derivation path for `index` (`index` maps to the account level). */
export function nostrPath(index: number): string {
  return `m/44'/1237'/${index}'/0/0`;
}

/** BIP-340 x-only public key = compressed SEC1 minus the parity byte. */
export function xonlyFromCompressed(compressed: Uint8Array): Uint8Array {
  if (compressed.length !== 33) {
    throw new KobeError("crypto", "nostr: compressed pubkey must be 33 bytes");
  }
  return compressed.subarray(1);
}
