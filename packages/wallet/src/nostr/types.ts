/**
 * Public types of the @qntx/wallet/nostr subpath — the only place in this package that imports
 *
 * @qntx/nostr. Secret data never appears here.
 */
import type { Event, NostrSigner } from "@qntx/nostr";
import type { Rumor } from "@qntx/nostr/nips/nip59";

import type {
  DerivedNostrKey,
  ExportedSecret,
  InitialFactor,
  NostrKeyInfo,
  NostrKeyRef,
  UnlockFactor,
  WalletErrorCode,
} from "../types.ts";

export type { DerivedNostrKey, NostrKeyInfo, NostrKeyRef } from "../types.ts";

export type NostrUnwrapResult = { readonly ok: Rumor } | { readonly err: WalletErrorCode };

/** A proxy NostrSigner: the kernel key is resolved per call, so it survives lock/unlock cycles. */
export type WalletSigner = {
  readonly unwrapGiftWraps: (
    events: ReadonlyArray<Event>,
  ) => Promise<ReadonlyArray<NostrUnwrapResult>>;
} & NostrSigner;

export type NostrImportKeyInput =
  | { readonly nsec: string }
  | { readonly ncryptsec: string; readonly password: string };

export type NostrExportKeyFormat =
  | { readonly kind: "nsec" }
  | { readonly kind: "ncryptsec"; readonly password: string };

export type NostrApi = {
  readonly signer: (ref: NostrKeyRef) => WalletSigner;
  /** Public keys a wallet's account groups would derive — discovery before deriveKey. */
  readonly discover: (
    walletId: string,
    from: number,
    count: number,
  ) => Promise<ReadonlyArray<DerivedNostrKey>>;
  readonly deriveKey: (walletId: string, groupIndex: number) => Promise<NostrKeyInfo>;
  readonly importKey: (
    input: NostrImportKeyInput,
    options?: { readonly factor?: InitialFactor },
  ) => Promise<NostrKeyInfo>;
  readonly generateKey: (options?: { readonly factor?: InitialFactor }) => Promise<NostrKeyInfo>;
  readonly createNip46ClientKey: () => Promise<NostrKeyInfo>;
  readonly removeKey: (ref: NostrKeyRef, verify?: UnlockFactor) => Promise<void>;
  /** One-shot key export; requires re-verification every call. */
  readonly exportKey: (
    ref: NostrKeyRef,
    format: NostrExportKeyFormat,
    verify: UnlockFactor,
  ) => Promise<ExportedSecret>;
};
