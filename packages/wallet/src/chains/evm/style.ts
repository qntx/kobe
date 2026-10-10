import { DeriveError } from "../../errors/derive.ts";
import { assertU32Index } from "../../hd/derive.ts";

export type EvmDerivationStyle = "standard" | "ledger-live" | "ledger-legacy";

const EVM_PATHS: Record<EvmDerivationStyle, (i: number) => string> = {
  standard: (i) => `m/44'/60'/0'/0/${i}`,
  "ledger-live": (i) => `m/44'/60'/${i}'/0/0`,
  "ledger-legacy": (i) => `m/44'/60'/0'/${i}`,
};

const ACCEPTED = [
  "standard",
  "metamask",
  "trezor",
  "bip44",
  "ledger-live",
  "ledgerlive",
  "live",
  "ledger-legacy",
  "ledgerlegacy",
  "legacy",
  "mew",
] as const;

/** Canonical path for style + index. @throws DeriveError input on bad index */
export function evmPath(style: EvmDerivationStyle, index: number): string {
  return EVM_PATHS[style](assertU32Index(index, "index"));
}

/** Case-insensitive alias parse. Unknown token → DeriveError input. */
export function parseEvmStyle(token: string): EvmDerivationStyle {
  switch (token.trim().toLowerCase()) {
    case "standard":
    case "metamask":
    case "trezor":
    case "bip44":
      return "standard";
    case "ledger-live":
    case "ledgerlive":
    case "live":
      return "ledger-live";
    case "ledger-legacy":
    case "ledgerlegacy":
    case "legacy":
    case "mew":
      return "ledger-legacy";
    default:
      throw new DeriveError(
        "input",
        `unknown evm derivation style '${token}' (accepted: ${ACCEPTED.join(", ")})`,
      );
  }
}
