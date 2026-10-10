import { DeriveError } from "../../errors/derive.ts";
import { assertU32Index } from "../../hd/derive.ts";

/**
 * Solana derivation-path layouts, named after the path shape, not a vendor.
 *
 * | Style          | Path layout          | Compatible wallets                                          |
 * | -------------- | -------------------- | ----------------------------------------------------------- |
 * | `bip44-change` | `m/44'/501'/{i}'/0'` | Phantom, Solflare, Backpack, `MetaMask`, OKX, solana-keygen |
 * | `bip44`        | `m/44'/501'/{i}'`    | Trust Wallet, Ledger Live, Keystone                         |
 * | `legacy`       | `m/501'/{i}'/0'/0'`  | Sollet (deprecated — import only)                           |
 */
export type SvmDerivationStyle = "bip44-change" | "bip44" | "legacy";

const ACCEPTED = [
  "bip44-change",
  "bip44",
  "legacy",
  "standard",
  "phantom",
  "backpack",
  "solflare",
  "trezor",
  "trust",
  "trustwallet",
  "ledger",
  "ledger-live",
  "ledgerlive",
  "live",
  "keystone",
  "old",
  "sollet",
] as const;

const SVM_PATHS: Record<SvmDerivationStyle, (i: number) => string> = {
  "bip44-change": (i) => `m/44'/501'/${i}'/0'`,
  bip44: (i) => `m/44'/501'/${i}'`,
  legacy: (i) => `m/501'/${i}'/0'/0'`,
};

export function svmPath(style: SvmDerivationStyle, index: number): string {
  return SVM_PATHS[style](assertU32Index(index, "index"));
}

export function parseSvmStyle(token: string): SvmDerivationStyle {
  switch (token.trim().toLowerCase()) {
    case "bip44-change":
    case "standard":
    case "phantom":
    case "backpack":
    case "solflare":
    case "trezor":
      return "bip44-change";
    case "bip44":
    case "trust":
    case "trustwallet":
    case "ledger":
    case "ledger-live":
    case "ledgerlive":
    case "live":
    case "keystone":
      return "bip44";
    case "legacy":
    case "old":
    case "sollet":
      return "legacy";
    default:
      throw new DeriveError(
        "input",
        `unknown svm derivation style '${token}' (accepted: ${ACCEPTED.join(", ")})`,
      );
  }
}
