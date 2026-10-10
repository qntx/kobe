import { base64urlnopad } from "@scure/base";
import { sha256Bytes } from "../../crypto/index.ts";
import { DeriveError } from "../../errors/derive.ts";

export const DEEP_HASH_LEN = 48;
export const SIGNATURE_LEN = 65;

export function arweavePath(index: number): string {
  return `m/44'/472'/0'/0/${index}`;
}

export function arweaveBase64Url(data: Uint8Array): string {
  return base64urlnopad.encode(data);
}

function requireCompressed(pk: Uint8Array): Uint8Array {
  if (pk.length !== 33 || (pk[0] !== 0x02 && pk[0] !== 0x03)) {
    throw new DeriveError("crypto", "arweave: expected 33-byte compressed secp256k1 public key");
  }
  return pk;
}

/** Protocol address: `Base64URL_nopad(SHA-256(compressed_pk))`. */
export function arweaveAddressFromCompressed(compressed: Uint8Array): string {
  return arweaveBase64Url(sha256Bytes(requireCompressed(compressed)));
}

/** Recovered-owner string: `Base64URL_nopad(compressed_pk)`. */
export function arweaveOwnerFromCompressed(compressed: Uint8Array): string {
  return arweaveBase64Url(requireCompressed(compressed));
}

/** Tx id: `Base64URL_nopad(SHA-256(signature_65))`. */
export function arweaveTransactionId(signature65: Uint8Array): string {
  if (signature65.length !== SIGNATURE_LEN) {
    throw new DeriveError(
      "crypto",
      `arweave tx id: signature must be ${SIGNATURE_LEN} bytes, got ${signature65.length}`,
    );
  }
  return arweaveBase64Url(sha256Bytes(signature65));
}
