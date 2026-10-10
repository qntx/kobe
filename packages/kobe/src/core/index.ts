/**
 * BIP-39 / BIP-32 wallet core (`@qntx/kobe/core`).
 *
 * The leaf layer of the package: `../nostr` may import `../core`, never the other way around. See
 * `parity.json` for the capabilities shared with the Rust `kobe-*` crates and `vectors/README.md`
 * for the error-code contract.
 */
export type { DerivedAccount, DerivedPublicKey } from "./account.ts";
export type { DerivedSecp256k1Key } from "./bip32.ts";
export { KobeError, type KobeErrorCode } from "./error.ts";
export { SecretKey } from "./secret.ts";
export type { RecoverableSignature } from "./signature.ts";
export { expandMnemonic } from "./expand.ts";
export { type GenerateWalletOptions, isValidMnemonic, Wallet, type WordCount } from "./wallet.ts";
