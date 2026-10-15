/**
 * The nostr module's method table and wire validators. The protocol stays free of @qntx/nostr
 * imports — even types — so the event shapes it validates are declared here structurally; a
 * type-level test in packages/wallet/tests pins them assignable to and from @qntx/nostr's
 * Event/UnsignedEvent/Rumor.
 */
import type { DerivedNostrKey, NostrKeyInfo, WalletErrorCode } from "../types.ts";
import {
  factor,
  groupIndex,
  MAX_BATCH,
  MAX_SNAPSHOT_ITEMS,
  MAX_TAG_ITEM,
  MAX_TAG_ITEMS,
  MAX_TAGS,
  MAX_TEXT,
  publicKey,
  safeTime,
  sessionId,
  walletErrorCode,
  walletId,
} from "./core.ts";
import type { Factor } from "./core.ts";
import type { MethodSpec, NullValue } from "./index.ts";
import type { Validator } from "./validate.ts";
import { arr, bool, bytes, int, literal, nullValue, obj, opt, str, union } from "./validate.ts";

/**
 * The unsigned event input the kernel signs. `pubkey` is optional: callers may omit it and the
 * kernel fills the signing key's own. Structurally compatible with @qntx/nostr's UnsignedEvent.
 */
export type UnsignedEventInput = {
  readonly kind: number;
  readonly created_at: number;
  readonly tags: ReadonlyArray<ReadonlyArray<string>>;
  readonly content: string;
  readonly pubkey?: string;
};

/** The signed event the kernel returns — the Nostr event minus `id`-less forms. */
export type SignedEvent = {
  readonly id: string;
  readonly pubkey: string;
  readonly sig: string;
  readonly kind: number;
  readonly created_at: number;
  readonly tags: ReadonlyArray<ReadonlyArray<string>>;
  readonly content: string;
};

/** A NIP-59 rumor: an unsigned event carrying a computed `id` but no `sig`. */
export type Rumor = {
  readonly id: string;
  readonly pubkey: string;
  readonly kind: number;
  readonly created_at: number;
  readonly tags: ReadonlyArray<ReadonlyArray<string>>;
  readonly content: string;
};

export type NostrImportInput =
  | { readonly kind: "nsec"; readonly nsec: Uint8Array }
  | { readonly kind: "ncryptsec"; readonly ncryptsec: string; readonly password: Uint8Array };

export type NostrExportFormat =
  | { readonly kind: "nsec" }
  | { readonly kind: "ncryptsec"; readonly password: Uint8Array };

/** One "import/generate a key" result: the key's public info plus the session it may have opened. */
export type KeyResult = { readonly key: NostrKeyInfo; readonly session: string };

export type UnwrapResult = { readonly ok: Rumor } | { readonly err: WalletErrorCode };

const hex128: Validator<string> = str(128, /^[0-9a-f]{128}$/);

const nostrKeyRef = union(
  obj({ kind: literal("derived"), walletId, groupIndex }),
  obj({ kind: literal("standalone"), id: publicKey }),
  obj({ kind: literal("nip46-client"), id: publicKey }),
);

// `backedUp` exists only on the standalone origins — the kernel never emits it for derived or
// nip46-client keys, and a peer that does is untrustworthy.
export const nostrKeyInfo: Validator<NostrKeyInfo> = union(
  obj({
    ref: nostrKeyRef,
    publicKey,
    origin: union(literal("nsec"), literal("ncryptsec"), literal("generated")),
    backedUp: bool,
    createdAt: safeTime,
  }),
  obj({
    ref: nostrKeyRef,
    publicKey,
    origin: union(literal("derived"), literal("nip46-client")),
    createdAt: safeTime,
  }),
);

/** The nostr section of the status payload, composed by protocol/index.ts. */
export const nostrStatus: Validator<{ readonly keys: ReadonlyArray<NostrKeyInfo> }> = obj({
  keys: arr(nostrKeyInfo, MAX_SNAPSHOT_ITEMS),
});

const keyResult: Validator<KeyResult> = obj({ key: nostrKeyInfo, session: sessionId });

const derivedNostrKey: Validator<DerivedNostrKey> = obj({ groupIndex, publicKey });

const tags: Validator<ReadonlyArray<ReadonlyArray<string>>> = arr(
  arr(str(MAX_TAG_ITEM), MAX_TAG_ITEMS),
  MAX_TAGS,
);

const signEventInput: Validator<UnsignedEventInput> = obj({
  kind: int(0, 65535),
  created_at: safeTime,
  tags,
  content: str(MAX_TEXT),
  pubkey: opt(publicKey),
});

const signedEvent: Validator<SignedEvent> = obj({
  id: publicKey,
  pubkey: publicKey,
  sig: hex128,
  kind: int(0, 65535),
  created_at: safeTime,
  tags,
  content: str(MAX_TEXT),
});

const rumor: Validator<Rumor> = obj({
  id: publicKey,
  pubkey: publicKey,
  kind: int(0, 65535),
  created_at: safeTime,
  tags,
  content: str(MAX_TEXT),
});

const nostrImportInput: Validator<NostrImportInput> = union(
  obj({ kind: literal("nsec"), nsec: bytes(1, 256) }),
  obj({ kind: literal("ncryptsec"), ncryptsec: str(512, /^ncryptsec1/), password: bytes(1, 1024) }),
);

const nostrExportFormat: Validator<NostrExportFormat> = union(
  obj({ kind: literal("nsec") }),
  obj({ kind: literal("ncryptsec"), password: bytes(1, 1024) }),
);

const textParams = obj({ publicKey, peer: publicKey, text: str(MAX_TEXT) });
const textResult = str(MAX_TEXT * 4);

export const NOSTR_METHODS: {
  readonly "nostr.discover": MethodSpec<
    { readonly walletId: string; readonly from: number; readonly count: number },
    { readonly keys: ReadonlyArray<DerivedNostrKey> }
  >;
  readonly "nostr.deriveKey": MethodSpec<
    { readonly walletId: string; readonly groupIndex: number },
    NostrKeyInfo
  >;
  readonly "nostr.importKey": MethodSpec<
    { readonly input: NostrImportInput; readonly factor?: Factor },
    KeyResult
  >;
  readonly "nostr.generateKey": MethodSpec<{ readonly factor?: Factor }, KeyResult>;
  readonly "nostr.createNip46ClientKey": MethodSpec<NullValue, NostrKeyInfo>;
  readonly "nostr.removeKey": MethodSpec<
    { readonly publicKey: string; readonly verify?: Factor },
    NullValue
  >;
  readonly "nostr.exportKey": MethodSpec<
    { readonly verify: Factor; readonly publicKey: string; readonly format: NostrExportFormat },
    Uint8Array
  >;
  readonly "nostr.signEvent": MethodSpec<
    { readonly publicKey: string; readonly event: UnsignedEventInput },
    SignedEvent
  >;
  readonly "nostr.nip04Encrypt": MethodSpec<
    { readonly publicKey: string; readonly peer: string; readonly text: string },
    string
  >;
  readonly "nostr.nip04Decrypt": MethodSpec<
    { readonly publicKey: string; readonly peer: string; readonly text: string },
    string
  >;
  readonly "nostr.nip44Encrypt": MethodSpec<
    { readonly publicKey: string; readonly peer: string; readonly text: string },
    string
  >;
  readonly "nostr.nip44Decrypt": MethodSpec<
    { readonly publicKey: string; readonly peer: string; readonly text: string },
    string
  >;
  readonly "nostr.unwrapGiftWraps": MethodSpec<
    { readonly publicKey: string; readonly events: ReadonlyArray<SignedEvent> },
    { readonly results: ReadonlyArray<UnwrapResult> }
  >;
} = {
  "nostr.discover": {
    session: true,
    params: obj({ walletId, from: groupIndex, count: int(1, 20) }),
    result: obj({ keys: arr(derivedNostrKey, 20) }),
  },
  "nostr.deriveKey": {
    session: true,
    params: obj({ walletId, groupIndex }),
    result: nostrKeyInfo,
  },
  "nostr.importKey": {
    session: false,
    params: obj({ input: nostrImportInput, factor: opt(factor) }),
    result: keyResult,
  },
  "nostr.generateKey": {
    session: false,
    params: obj({ factor: opt(factor) }),
    result: keyResult,
  },
  "nostr.createNip46ClientKey": { session: true, params: nullValue, result: nostrKeyInfo },
  "nostr.removeKey": {
    session: true,
    params: obj({ publicKey, verify: opt(factor) }),
    result: nullValue,
  },
  "nostr.exportKey": {
    session: true,
    params: obj({ verify: factor, publicKey, format: nostrExportFormat }),
    result: bytes(16, 4096),
  },
  "nostr.signEvent": {
    session: true,
    params: obj({ publicKey, event: signEventInput }),
    result: signedEvent,
  },
  "nostr.nip04Encrypt": { session: true, params: textParams, result: textResult },
  "nostr.nip04Decrypt": { session: true, params: textParams, result: textResult },
  "nostr.nip44Encrypt": { session: true, params: textParams, result: textResult },
  "nostr.nip44Decrypt": { session: true, params: textParams, result: textResult },
  "nostr.unwrapGiftWraps": {
    session: true,
    params: obj({ publicKey, events: arr(signedEvent, MAX_BATCH) }),
    result: obj({
      results: arr(union(obj({ ok: rumor }), obj({ err: walletErrorCode })), MAX_BATCH),
    }),
  },
};
