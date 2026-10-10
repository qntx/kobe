import { VaultError } from "../errors/vault.ts";
import { walletFromEntropy } from "../hd/wallet.ts";
import type { Wallet } from "../hd/wallet.ts";
import { wipeBytes } from "../secret/dispose.ts";

const PRF_LEN = 32;

/**
 * Build a 12-word {@link Wallet} from a 32-byte PRF output: `walletFromEntropy(prf[0..16])` with no
 * passphrase.
 *
 * The PRF input is chosen by the application; the wallet only consumes the 32-byte output.
 *
 * @throws VaultError input if `prfOutput` is not exactly 32 bytes
 */
export function passkeyWallet(prfOutput: Uint8Array): Wallet {
  if (prfOutput.length !== PRF_LEN) {
    throw new VaultError("input", "vault: PRF output must be 32 bytes");
  }
  const entropy = prfOutput.slice(0, 16);
  try {
    return walletFromEntropy(entropy);
  } finally {
    wipeBytes(entropy);
  }
}
