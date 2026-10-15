/**
 * The public root of @qntx/wallet (design/entry.mdx): the Wallet interface, the immutable
 * WalletSnapshot, WalletError, the API interfaces and option types, and the public data types.
 * Kernel internals are never re-exported here — host packages use the "./host" subpath.
 */
export {
  WalletError,
  type AutoLockPolicy,
  type DataKeyApi,
  type DerivedNostrKey,
  type ExportApi,
  type ExportedSecret,
  type FactorInfo,
  type InitialFactor,
  type LockReason,
  type MnemonicDraft,
  type NostrApi,
  type NostrKeyInfo,
  type NostrKeyRef,
  type NostrUnwrapResult,
  type PasskeyConfig,
  type StatusPayload,
  type UnlockFactor,
  type VaultApi,
  type Wallet,
  type WalletCreated,
  type WalletErrorCode,
  type WalletInfo,
  type WalletLogger,
  type WalletOptions,
  type WalletSigner,
  type WalletSnapshot,
  type WalletsApi,
} from "./types.ts";
