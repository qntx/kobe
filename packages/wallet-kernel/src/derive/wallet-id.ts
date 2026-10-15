import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import type { HDKey } from "@scure/bip32";

import { KernelError } from "../errors.ts";

/**
 * Stable wallet identifier: lowercase hex of the first 8 bytes of
 * SHA-256(UTF-8("qntx-wallet/wallet-id/v1") ‖ master compressed public key). Derived from public
 * data only — safe to use as a record id.
 */
export function walletIdOf(master: HDKey): string {
  const { publicKey } = master;
  if (publicKey === null || publicKey.length !== 33) {
    throw new KernelError("integrity", "master key has no compressed public key");
  }
  return bytesToHex(
    sha256(concatBytes(utf8ToBytes("qntx-wallet/wallet-id/v1"), publicKey)).slice(0, 8),
  );
}
