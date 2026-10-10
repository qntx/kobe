import { assertU32Index } from "../core/derive.ts";

/**
 * EVM derivation styles — the tokens are exactly `DerivationStyle::as_str()` in `kobe-evm`.
 *
 * - `standard` — MetaMask/Trezor/BIP-44: `m/44'/60'/0'/0/{i}`
 * - `ledger-live` — Ledger Live: `m/44'/60'/{i}'/0/0`
 * - `ledger-legacy` — Ledger Legacy / MEW: `m/44'/60'/0'/{i}`
 */
export type EvmDerivationStyle = "standard" | "ledger-live" | "ledger-legacy";

/**
 * Canonical BIP-32 path for a style + index.
 *
 * @throws KobeError input on an out-of-range index
 */
export function evmPath(style: EvmDerivationStyle, index: number): string {
  const i = assertU32Index(index, "index");
  if (style === "standard") {
    return `m/44'/60'/0'/0/${i}`;
  }
  if (style === "ledger-live") {
    return `m/44'/60'/${i}'/0/0`;
  }
  return `m/44'/60'/0'/${i}`;
}
