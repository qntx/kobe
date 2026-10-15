import { KernelError } from "../errors.ts";
import { wipe } from "../secret/secret.ts";

/**
 * Passkey wallet entropy is the first 16 bytes of the WebAuthn PRF output (qntx/wallet's own
 * convention). Wipes `prf` in every case.
 */
export function entropyFromPrf(prf: Uint8Array): Uint8Array {
  try {
    if (prf.length !== 32) {
      throw new KernelError("invalid-input", "PRF output must be 32 bytes");
    }
    return prf.slice(0, 16);
  } finally {
    wipe(prf);
  }
}
