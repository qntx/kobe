/**
 * The E0 method table: method name → params/result validators and whether a session is required.
 * "Create or import" commands (createWithPasskey/restoreWithPasskey/createMnemonic/importMnemonic/
 * nostr.importKey/nostr.generateKey) are `session: false` here because the rule is dynamic: with an
 * uninitialized vault they carry `factor` and establish the vault in one commit; with an
 * established vault `factor` must be absent and a valid session is required.
 */
import type { Event, Tag } from "@qntx/nostr";
import type { Rumor } from "@qntx/nostr/nips/nip59";

import type {
  DerivedNostrKey,
  FactorInfo,
  LockReason,
  NostrKeyInfo,
  StatusPayload,
  WalletErrorCode,
  WalletInfo,
} from "../types.ts";
import type { KernelEvent, NullValue } from "./index.ts";
import type { Validator } from "./validate.ts";
import { arr, bool, bytes, int, literal, nullValue, obj, opt, str, union } from "./validate.ts";

export type MethodSpec<P, R> = {
  readonly session: boolean;
  readonly params: Validator<P>;
  readonly result: Validator<R>;
};

// Size caps (UTF-16 units for strings, bytes for Uint8Array). A whole message is capped at 1 MiB
// by the host; these bound individual fields.
const MAX_TEXT = 262_144;
const MAX_TAGS = 1024;
const MAX_TAG_ITEMS = 64;
const MAX_TAG_ITEM = 4096;
const MAX_BATCH = 256;
const MAX_SNAPSHOT_ITEMS = 4096;

const sessionId: Validator<string> = str(32, /^[0-9a-f]{32}$/);
const draftId: Validator<string> = str(32, /^[0-9a-f]{32}$/);
const walletId: Validator<string> = str(16, /^[0-9a-f]{16}$/);
const publicKey: Validator<string> = str(64, /^[0-9a-f]{64}$/);
const hex128: Validator<string> = str(128, /^[0-9a-f]{128}$/);
const credentialId: Validator<string> = str(1364, /^[A-Za-z0-9_-]+$/);
const safeTime: Validator<number> = int(0, Number.MAX_SAFE_INTEGER);
const groupIndex: Validator<number> = int(0, 0x7fffffff);

export type Factor =
  | { readonly kind: "password"; readonly password: Uint8Array }
  | { readonly kind: "passkey"; readonly credentialId: Uint8Array; readonly prf: Uint8Array };

const factor: Validator<Factor> = union(
  obj({ kind: literal("password"), password: bytes(1, 1024) }),
  obj({ kind: literal("passkey"), credentialId: bytes(1, 1023), prf: bytes(32) }),
);

const factorInfo: Validator<FactorInfo> = union(
  obj({ kind: literal("hardware") }),
  obj({
    kind: literal("passkey"),
    id: sessionId,
    credentialId,
    createdAt: safeTime,
  }),
  obj({ kind: literal("password"), id: sessionId, createdAt: safeTime }),
);

const walletInfo: Validator<WalletInfo> = obj({
  walletId,
  origin: union(literal("passkey"), literal("mnemonic")),
  words: union(literal(12), literal(15), literal(18), literal(21), literal(24)),
  backedUp: bool,
  createdAt: safeTime,
});

const nostrKeyRef = union(
  obj({ kind: literal("derived"), walletId, groupIndex }),
  obj({ kind: literal("standalone"), id: publicKey }),
  obj({ kind: literal("nip46-client"), id: publicKey }),
);

const nostrKeyInfo: Validator<NostrKeyInfo> = obj({
  ref: nostrKeyRef,
  publicKey,
  origin: union(
    literal("derived"),
    literal("nsec"),
    literal("ncryptsec"),
    literal("generated"),
    literal("nip46-client"),
  ),
  createdAt: safeTime,
});

const statusPayload: Validator<StatusPayload> = obj({
  protocol: literal(1),
  vault: union(
    literal("uninitialized"),
    literal("locked"),
    literal("unlocked"),
    literal("corrupted"),
  ),
  factors: arr(factorInfo, MAX_SNAPSHOT_ITEMS),
  wallets: arr(walletInfo, MAX_SNAPSHOT_ITEMS),
  nostrKeys: arr(nostrKeyInfo, MAX_SNAPSHOT_ITEMS),
});

export type CreatedResult = {
  readonly wallet: WalletInfo;
  readonly nostr: NostrKeyInfo;
  readonly session: string;
};

export type KeyResult = { readonly key: NostrKeyInfo; readonly session: string };

export type UnsignedEventInput = {
  readonly kind: number;
  readonly created_at: number;
  readonly tags: ReadonlyArray<ReadonlyArray<string>>;
  readonly content: string;
  readonly pubkey?: string;
};

export type NostrImportInput =
  | { readonly kind: "nsec"; readonly nsec: Uint8Array }
  | { readonly kind: "ncryptsec"; readonly ncryptsec: string; readonly password: Uint8Array };

export type NostrExportFormat =
  | { readonly kind: "nsec" }
  | { readonly kind: "ncryptsec"; readonly password: Uint8Array };

export type UnwrapResult = { readonly ok: Rumor } | { readonly err: WalletErrorCode };

const createdResult: Validator<CreatedResult> = obj({
  wallet: walletInfo,
  nostr: nostrKeyInfo,
  session: sessionId,
});
const keyResult: Validator<KeyResult> = obj({ key: nostrKeyInfo, session: sessionId });
const derivedNostrKey: Validator<DerivedNostrKey> = obj({ groupIndex, publicKey });

const tags: Validator<ReadonlyArray<Tag>> = arr(arr(str(MAX_TAG_ITEM), MAX_TAG_ITEMS), MAX_TAGS);
const signEventInput: Validator<UnsignedEventInput> = obj({
  kind: int(0, 65535),
  created_at: safeTime,
  tags,
  content: str(MAX_TEXT),
  pubkey: opt(publicKey),
});
const signedEvent: Validator<Event> = obj({
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

const walletErrorCode: Validator<WalletErrorCode> = union(
  literal("locked"),
  literal("cancelled"),
  literal("factor-unavailable"),
  literal("factor-invalidated"),
  literal("wrong-password"),
  literal("rate-limited"),
  literal("invalid-input"),
  literal("not-found"),
  literal("already-exists"),
  literal("integrity"),
  literal("crashed"),
);

export const METHODS: {
  readonly status: MethodSpec<NullValue, StatusPayload>;
  readonly "vault.unlock": MethodSpec<{ readonly factor: Factor }, { readonly session: string }>;
  readonly "vault.lock": MethodSpec<NullValue, NullValue>;
  readonly "vault.reset": MethodSpec<NullValue, NullValue>;
  readonly "vault.addFactor": MethodSpec<
    { readonly verify: Factor; readonly factor: Factor },
    FactorInfo
  >;
  readonly "vault.removeFactor": MethodSpec<
    { readonly verify: Factor; readonly id: string },
    NullValue
  >;
  readonly "wallet.createWithPasskey": MethodSpec<
    {
      readonly credentialId: Uint8Array;
      readonly prfWallet: Uint8Array;
      readonly factor?: Factor;
    },
    CreatedResult
  >;
  readonly "wallet.restoreWithPasskey": MethodSpec<
    {
      readonly credentialId: Uint8Array;
      readonly prfWallet: Uint8Array;
      readonly factor?: Factor;
    },
    CreatedResult
  >;
  readonly "wallet.createMnemonic": MethodSpec<
    { readonly words: 12 | 24; readonly factor?: Factor },
    { readonly draft: string; readonly words: Uint8Array; readonly quiz: ReadonlyArray<number> }
  >;
  readonly "wallet.confirmMnemonic": MethodSpec<
    { readonly draft: string; readonly answers: ReadonlyArray<Uint8Array> },
    CreatedResult
  >;
  readonly "wallet.discardMnemonic": MethodSpec<{ readonly draft: string }, NullValue>;
  readonly "wallet.importMnemonic": MethodSpec<
    { readonly mnemonic: Uint8Array; readonly factor?: Factor },
    CreatedResult
  >;
  readonly "wallet.discoverNostr": MethodSpec<
    { readonly walletId: string; readonly from: number; readonly count: number },
    { readonly keys: ReadonlyArray<DerivedNostrKey> }
  >;
  readonly "wallet.delete": MethodSpec<
    { readonly verify: Factor; readonly walletId: string },
    NullValue
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
  readonly "nostr.signEvent": MethodSpec<
    { readonly publicKey: string; readonly event: UnsignedEventInput },
    Event
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
    { readonly publicKey: string; readonly events: ReadonlyArray<Event> },
    { readonly results: ReadonlyArray<UnwrapResult> }
  >;
  readonly "export.mnemonic": MethodSpec<
    { readonly verify: Factor; readonly walletId: string },
    Uint8Array
  >;
  readonly "export.nostrKey": MethodSpec<
    { readonly verify: Factor; readonly publicKey: string; readonly format: NostrExportFormat },
    Uint8Array
  >;
  readonly "dataKeys.get": MethodSpec<{ readonly purpose: string }, Uint8Array>;
} = {
  status: { session: false, params: nullValue, result: statusPayload },
  "vault.unlock": {
    session: false,
    params: obj({ factor }),
    result: obj({ session: sessionId }),
  },
  "vault.lock": { session: false, params: nullValue, result: nullValue },
  "vault.reset": { session: false, params: nullValue, result: nullValue },
  "vault.addFactor": {
    session: true,
    params: obj({ verify: factor, factor }),
    result: factorInfo,
  },
  "vault.removeFactor": {
    session: true,
    params: obj({ verify: factor, id: sessionId }),
    result: nullValue,
  },
  "wallet.createWithPasskey": {
    session: false,
    params: obj({ credentialId: bytes(1, 1023), prfWallet: bytes(32), factor: opt(factor) }),
    result: createdResult,
  },
  "wallet.restoreWithPasskey": {
    session: false,
    params: obj({ credentialId: bytes(1, 1023), prfWallet: bytes(32), factor: opt(factor) }),
    result: createdResult,
  },
  "wallet.createMnemonic": {
    session: false,
    params: obj({ words: union(literal(12), literal(24)), factor: opt(factor) }),
    result: obj({
      draft: draftId,
      words: bytes(16, 1024),
      quiz: arr(int(0, 23), 3, 3),
    }),
  },
  "wallet.confirmMnemonic": {
    session: false,
    params: obj({ draft: draftId, answers: arr(bytes(1, 64), 3, 3) }),
    result: createdResult,
  },
  "wallet.discardMnemonic": {
    session: false,
    params: obj({ draft: draftId }),
    result: nullValue,
  },
  "wallet.importMnemonic": {
    session: false,
    params: obj({ mnemonic: bytes(1, 1024), factor: opt(factor) }),
    result: createdResult,
  },
  "wallet.discoverNostr": {
    session: true,
    params: obj({ walletId, from: groupIndex, count: int(1, 20) }),
    result: obj({ keys: arr(derivedNostrKey, 20) }),
  },
  "wallet.delete": {
    session: true,
    params: obj({ verify: factor, walletId }),
    result: nullValue,
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
  "export.mnemonic": {
    session: true,
    params: obj({ verify: factor, walletId }),
    result: bytes(16, 1024),
  },
  "export.nostrKey": {
    session: true,
    params: obj({ verify: factor, publicKey, format: nostrExportFormat }),
    result: bytes(16, 4096),
  },
  "dataKeys.get": {
    session: true,
    params: obj({ purpose: str(32, /^[a-z0-9-]{1,32}$/) }),
    result: bytes(32),
  },
};

export type MethodName = keyof typeof METHODS;
export type ParamsOf<M extends MethodName> = ReturnType<(typeof METHODS)[M]["params"]>;
export type ResultOf<M extends MethodName> = ReturnType<(typeof METHODS)[M]["result"]>;

const lockReason: Validator<LockReason> = union(
  literal("cold-start"),
  literal("user"),
  literal("idle"),
  literal("background"),
  literal("expired"),
  literal("crashed"),
);

const errorPayload = obj({ code: walletErrorCode, retryAt: opt(safeTime) });

/** Host-side validators: `kernelEvent` covers the two push messages. */
export const kernelEvent: Validator<KernelEvent> = union(
  obj({ v: literal(1), event: literal("status"), status: statusPayload }),
  obj({ v: literal(1), event: literal("locked"), reason: lockReason }),
);

/** Validates the `err` payload of a response; `ok` is checked against `METHODS[m].result`. */
export const responseError: Validator<{ code: WalletErrorCode; retryAt?: number | undefined }> =
  errorPayload;
