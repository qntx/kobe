import { DeriveError } from "../../errors/derive.ts";
import { assertU32Index } from "../../hd/derive.ts";

export type SvmDerivationStyle = "standard" | "trust" | "ledger-live" | "legacy";

const ACCEPTED = [
  "standard",
  "phantom",
  "backpack",
  "solflare",
  "trezor",
  "trust",
  "trustwallet",
  "ledger",
  "ledger-native",
  "ledgernative",
  "keystone",
  "ledger-live",
  "ledgerlive",
  "live",
  "legacy",
  "old",
  "sollet",
] as const;

export function svmPath(style: SvmDerivationStyle, index: number): string {
  const i = assertU32Index(index, "index");
  switch (style) {
    case "standard":
      return `m/44'/501'/${i}'/0'`;
    case "trust":
      return `m/44'/501'/${i}'`;
    case "ledger-live":
      return `m/44'/501'/${i}'/0'/0'`;
    case "legacy":
      return `m/501'/${i}'/0'/0'`;
  }
}

export function parseSvmStyle(token: string): SvmDerivationStyle {
  switch (token.trim().toLowerCase()) {
    case "standard":
    case "phantom":
    case "backpack":
    case "solflare":
    case "trezor":
      return "standard";
    case "trust":
    case "trustwallet":
    case "ledger":
    case "ledger-native":
    case "ledgernative":
    case "keystone":
      return "trust";
    case "ledger-live":
    case "ledgerlive":
    case "live":
      return "ledger-live";
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
