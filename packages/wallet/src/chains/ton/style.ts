import { DeriveError } from "../../errors/derive.ts";
import { assertU32Index } from "../../hd/derive.ts";

export type TonDerivationStyle = "standard" | "ledger-live";

const ACCEPTED = [
  "standard",
  "tonkeeper",
  "mytonwallet",
  "trust",
  "ledger-live",
  "ledgerlive",
  "live",
] as const;

/** Canonical path for style + index. @throws DeriveError input on bad index */
export function tonPath(style: TonDerivationStyle, index: number): string {
  const i = assertU32Index(index, "index");
  switch (style) {
    case "standard":
      return `m/44'/607'/${i}'`;
    case "ledger-live":
      return `m/44'/607'/${i}'/0'/0'`;
  }
}

/**
 * Case-insensitive alias parse. Unknown token → DeriveError input.
 */
export function parseTonStyle(token: string): TonDerivationStyle {
  switch (token.trim().toLowerCase()) {
    case "standard":
    case "tonkeeper":
    case "mytonwallet":
    case "trust":
      return "standard";
    case "ledger-live":
    case "ledgerlive":
    case "live":
      return "ledger-live";
    default:
      throw new DeriveError(
        "input",
        `unknown ton derivation style '${token}' (accepted: ${ACCEPTED.join(", ")})`,
      );
  }
}
