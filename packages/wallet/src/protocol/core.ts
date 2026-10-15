/**
 * The core method table: vault, wallet and data-key commands — nothing protocol-specific. "Create
 * or import" commands (createWithPasskey/restoreWithPasskey/createMnemonic/importMnemonic) are
 * `session: false` here because the rule is dynamic: with an uninitialized vault they carry
 * `factor` and establish the vault in one commit; with an established vault `factor` must be absent
 * and a valid session is required.
 *
 * The shared wire validators (factor, wallet info, ids) live here too so the nostr module's table
 * can reuse them — `protocol/nostr.ts` imports only from this file.
 */
import type { FactorInfo, WalletErrorCode, WalletInfo } from "../types.ts";
import type { NullValue } from "./index.ts";
import type { Validator } from "./validate.ts";
import { arr, bool, bytes, int, literal, nullValue, obj, opt, str, union } from "./validate.ts";

export type MethodSpec<P, R> = {
  readonly session: boolean;
  readonly params: Validator<P>;
  readonly result: Validator<R>;
};

// Size caps (UTF-16 units for strings, bytes for Uint8Array). These bound individual fields; the
// whole-request cap MAX_REQUEST_BYTES (protocol/index.ts) is enforced by host and kernel.
export const MAX_TEXT = 262_144;
export const MAX_TAGS = 1024;
export const MAX_TAG_ITEMS = 64;
export const MAX_TAG_ITEM = 4096;
export const MAX_BATCH = 256;
export const MAX_SNAPSHOT_ITEMS = 4096;

export const sessionId: Validator<string> = str(32, /^[0-9a-f]{32}$/);
export const draftId: Validator<string> = str(32, /^[0-9a-f]{32}$/);
export const walletId: Validator<string> = str(16, /^[0-9a-f]{16}$/);
export const publicKey: Validator<string> = str(64, /^[0-9a-f]{64}$/);
export const credentialId: Validator<string> = str(1364, /^[A-Za-z0-9_-]+$/);
export const safeTime: Validator<number> = int(0, Number.MAX_SAFE_INTEGER);
export const groupIndex: Validator<number> = int(0, 0x7fffffff);

export type Factor =
  | { readonly kind: "password"; readonly password: Uint8Array }
  | { readonly kind: "passkey"; readonly credentialId: Uint8Array; readonly prf: Uint8Array };

export const factor: Validator<Factor> = union(
  obj({ kind: literal("password"), password: bytes(1, 1024) }),
  obj({ kind: literal("passkey"), credentialId: bytes(1, 1023), prf: bytes(32) }),
);

export const factorInfo: Validator<FactorInfo> = union(
  obj({ kind: literal("hardware") }),
  obj({
    kind: literal("passkey"),
    id: sessionId,
    credentialId,
    createdAt: safeTime,
  }),
  obj({ kind: literal("password"), id: sessionId, createdAt: safeTime }),
);

export const walletInfo: Validator<WalletInfo> = obj({
  walletId,
  origin: union(literal("passkey"), literal("mnemonic")),
  words: union(literal(12), literal(15), literal(18), literal(21), literal(24)),
  backedUp: bool,
  createdAt: safeTime,
});

export const walletErrorCode: Validator<WalletErrorCode> = union(
  literal("locked"),
  literal("cancelled"),
  literal("factor-unavailable"),
  literal("factor-invalidated"),
  literal("wrong-password"),
  literal("wrong-passkey"),
  literal("rate-limited"),
  literal("invalid-input"),
  literal("not-found"),
  literal("already-exists"),
  literal("conflict"),
  literal("unsupported"),
  literal("unavailable"),
  literal("integrity"),
  literal("crashed"),
);

/**
 * The result of every "create or import" wallet command: the new wallet's public info plus the
 * session it opened. Creating a wallet derives no protocol keys — modules add keys separately.
 */
export type CreatedResult = {
  readonly wallet: WalletInfo;
  readonly session: string;
};

const createdResult: Validator<CreatedResult> = obj({ wallet: walletInfo, session: sessionId });

// `status` itself is a core method, but its result validator composes every module's status
// section — it is wired in protocol/index.ts, not here.
export const CORE_METHODS: {
  readonly "vault.unlock": MethodSpec<{ readonly factor: Factor }, { readonly session: string }>;
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
  readonly "wallet.exportMnemonic": MethodSpec<
    { readonly verify: Factor; readonly walletId: string },
    Uint8Array
  >;
  readonly "wallet.delete": MethodSpec<
    { readonly verify: Factor; readonly walletId: string },
    NullValue
  >;
  readonly "dataKeys.get": MethodSpec<{ readonly purpose: string }, Uint8Array>;
} = {
  "vault.unlock": {
    session: false,
    params: obj({ factor }),
    result: obj({ session: sessionId }),
  },
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
  "wallet.exportMnemonic": {
    session: true,
    params: obj({ verify: factor, walletId }),
    result: bytes(16, 1024),
  },
  "wallet.delete": {
    session: true,
    params: obj({ verify: factor, walletId }),
    result: nullValue,
  },
  "dataKeys.get": {
    session: true,
    params: obj({ purpose: str(32, /^[a-z0-9-]{1,32}$/) }),
    result: bytes(32),
  },
};
