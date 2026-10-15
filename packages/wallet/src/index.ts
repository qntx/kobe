/**
 * The public root of @qntx/wallet (design/entry.mdx): the Wallet interface, the immutable
 * WalletSnapshot, WalletError, the API interfaces and option types, and the public data types.
 * Kernel internals are never re-exported here — host packages use the "./host" subpath, and the
 * Nostr API lives in the "./nostr" subpath (nostr(wallet)).
 */
export {
  WalletError,
  type AutoLockPolicy,
  type DataKeyApi,
  type DerivedNostrKey,
  type ExportedSecret,
  type FactorInfo,
  type InitialFactor,
  type LockReason,
  type MnemonicDraft,
  type NostrKeyInfo,
  type NostrKeyRef,
  type PasskeyConfig,
  type StatusPayload,
  type UnlockFactor,
  type VaultApi,
  type Wallet,
  type WalletErrorCode,
  type WalletInfo,
  type WalletOptions,
  type WalletSnapshot,
  type WalletsApi,
} from "./types.ts";
