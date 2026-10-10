/** HD public surface (`wallet/hd`). */
export type { DerivedSecp256k1Key } from "../bip32/index.ts";
export { DeriveError, type DeriveErrorCode, isDeriveError } from "../errors/derive.ts";
export type { DerivedEd25519Key } from "../slip10/index.ts";
export {
  createDerivedAccount,
  type CreateDerivedAccountInput,
  type DerivedAccount,
  type DerivedPublicKey,
  snapshotPublicKey,
  type SvmAccount,
} from "./account.ts";
export { assertU32Index, type ChainDeriver, deriveRange, U32_MAX } from "./derive.ts";
export { expandMnemonic } from "./expand.ts";
export { MNEMONIC_LANGUAGES, parseMnemonicLanguage, type MnemonicLanguage } from "./language.ts";
export {
  generateWallet,
  isValidMnemonic,
  mnemonicToEntropyBytes,
  type GenerateWalletOptions,
  type Wallet,
  type WordCount,
  walletFromEntropy,
  walletFromMnemonic,
  walletFromMnemonicExpanded,
} from "./wallet.ts";
