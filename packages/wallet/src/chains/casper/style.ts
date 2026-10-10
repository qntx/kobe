import { DeriveError } from "../../errors/derive.ts";
import { assertU32Index } from "../../hd/derive.ts";

export type CasperKeyAlgo = "secp256k1" | "ed25519";

const ACCEPTED = ["secp256k1", "secp", "ecdsa", "ed25519", "ed", "eddsa"] as const;

/** Canonical path for algo + index. @throws DeriveError input on bad index */
export function casperPath(algo: CasperKeyAlgo, index: number): string {
  const i = assertU32Index(index, "index");
  switch (algo) {
    case "secp256k1":
      return `m/44'/506'/0'/0/${i}`;
    case "ed25519":
      return `m/44'/506'/0'/0'/${i}'`;
  }
}

/** Case-insensitive alias parse. Unknown token → DeriveError input. */
export function parseCasperAlgo(token: string): CasperKeyAlgo {
  switch (token.trim().toLowerCase()) {
    case "secp256k1":
    case "secp":
    case "ecdsa":
      return "secp256k1";
    case "ed25519":
    case "ed":
    case "eddsa":
      return "ed25519";
    default:
      throw new DeriveError(
        "input",
        `unknown casper key algo '${token}' (accepted: ${ACCEPTED.join(", ")})`,
      );
  }
}
