import { wipeBytes } from "../core/bytes.ts";
import { KobeError } from "../core/error.ts";
import { Wallet } from "../core/wallet.ts";

const PRF_LEN = 32;

/**
 * Build a 12-word {@link Wallet} from a 32-byte PRF output: `Wallet.fromEntropy(prf[0..16])` with no
 * passphrase.
 *
 * The PRF input is chosen by the application; kobe only consumes the 32-byte output.
 *
 * @throws KobeError input if `prfOutput` is not exactly 32 bytes
 */
export function passkeyWallet(prfOutput: Uint8Array): Wallet {
  if (prfOutput.length !== PRF_LEN) {
    throw new KobeError("input", "vault: PRF output must be 32 bytes");
  }
  const entropy = prfOutput.slice(0, 16);
  try {
    return Wallet.fromEntropy(entropy);
  } finally {
    wipeBytes(entropy);
  }
}
