/** Public types of @qntx/wallet, per design/entry.mdx. Secret data never appears here. */
export type LockReason = "cold-start" | "user" | "idle" | "background" | "expired" | "crashed";

export type FactorInfo =
  | { readonly kind: "hardware" }
  | {
      readonly kind: "passkey";
      readonly id: string;
      /** Base64url, public data — the main side passes it as allowCredentials. */
      readonly credentialId: string;
      readonly createdAt: number;
    }
  | { readonly kind: "password"; readonly id: string; readonly createdAt: number };

export type WalletInfo = {
  readonly walletId: string;
  readonly origin: "passkey" | "mnemonic";
  readonly words: 12 | 15 | 18 | 21 | 24;
  readonly backedUp: boolean;
  readonly createdAt: number;
};

export type NostrKeyRef =
  | { readonly kind: "derived"; readonly walletId: string; readonly groupIndex: number }
  | { readonly kind: "standalone"; readonly id: string }
  | { readonly kind: "nip46-client"; readonly id: string };

export type NostrKeyInfo = {
  readonly ref: NostrKeyRef;
  readonly publicKey: string; // 64 lowercase hex
  readonly origin: "derived" | "nsec" | "ncryptsec" | "generated" | "nip46-client";
  readonly createdAt: number;
};

/** One entry of a `nostr.discover` result: the public key an account group would produce. */
export type DerivedNostrKey = { readonly groupIndex: number; readonly publicKey: string };

export type WalletErrorCode =
  | "locked"
  | "cancelled"
  | "factor-unavailable"
  | "factor-invalidated"
  | "wrong-password"
  | "rate-limited"
  | "invalid-input"
  | "not-found"
  | "already-exists"
  | "integrity"
  | "crashed";

/**
 * `status` result / status event payload. Locked snapshots come from unauthenticated headers;
 * "corrupted" means the vault data itself failed to load or verify (reset is the only way out).
 * Each protocol module contributes one section (here: `nostr`).
 */
export type StatusPayload = {
  readonly protocol: 1;
  readonly vault: "uninitialized" | "locked" | "unlocked" | "corrupted";
  readonly factors: ReadonlyArray<FactorInfo>;
  readonly wallets: ReadonlyArray<WalletInfo>;
  readonly nostr: { readonly keys: ReadonlyArray<NostrKeyInfo> };
};

/** One error class for the whole API; `code` carries the distinction. Messages never echo input. */
export class WalletError extends Error {
  readonly code: WalletErrorCode;
  readonly retryAt: number | undefined;

  constructor(code: WalletErrorCode, message: string, retryAt?: number) {
    super(message);
    this.name = "WalletError";
    this.code = code;
    this.retryAt = retryAt;
  }
}

/** A factor the user proves again for a guarded operation (Web/Node). */
export type UnlockFactor =
  | { readonly kind: "passkey" }
  | { readonly kind: "password"; readonly password: string };

/**
 * A factor being created; `hardware` exists only on React Native. `name` is the passkey
 * credential's display name — the host validates it before the ceremony (1–64 characters).
 */
export type InitialFactor =
  | { readonly kind: "hardware" }
  | { readonly kind: "passkey"; readonly name: string }
  | { readonly kind: "password"; readonly password: string };

/** WebAuthn RP identity + PRF salt labels the host configures once (distinct strings). */
export type PasskeyConfig = {
  /** RP id — the origin's effective domain or a registrable parent of it (e.g. meowl.social). */
  readonly rpId: string;
  readonly rpName: string;
  readonly walletSalt: string;
  readonly vaultSalt: string;
};

export type AutoLockPolicy =
  | { readonly platform: "native"; readonly backgroundSeconds: 0 | 60 | 300 | 900 }
  | { readonly platform: "web"; readonly idleMinutes: 5 | 15 | 60 };

/** Structured events only — never anything secret-bearing. */
export type WalletLogger = (event: { readonly name: string }) => void;

export type WalletOptions = {
  readonly passkey: PasskeyConfig;
  readonly autoLock: AutoLockPolicy;
  readonly logger?: WalletLogger;
};

export type WalletSnapshot = {
  readonly vault: "uninitialized" | "locked" | "unlocked" | "corrupted";
  readonly lockReason: LockReason | undefined;
  readonly verifying: boolean; // a user verification is in flight
  readonly factors: ReadonlyArray<FactorInfo>;
  readonly wallets: ReadonlyArray<WalletInfo>;
  readonly nostr: { readonly keys: ReadonlyArray<NostrKeyInfo> };
};

/** A one-shot secret buffer: `read` detaches the bytes to the caller, `wipe` zeroes them. */
export type ExportedSecret = {
  readonly read: () => Uint8Array; // UTF-8 text; single use — the second call throws
  readonly wipe: () => void;
};

export type MnemonicDraft = {
  readonly words: ExportedSecret; // read once, then the host is responsible for wiping
  readonly quiz: ReadonlyArray<number>; // three positions the enclave picked
  readonly confirm: (answers: ReadonlyArray<string>) => Promise<WalletInfo>;
  readonly discard: () => Promise<void>;
};

export type VaultApi = {
  readonly unlock: (factor?: UnlockFactor) => Promise<void>;
  readonly lock: () => Promise<void>;
  readonly addFactor: (factor: InitialFactor, verify: UnlockFactor) => Promise<FactorInfo>;
  readonly removeFactor: (id: string, verify: UnlockFactor) => Promise<void>; // ≥1 factor remains
  readonly reset: () => Promise<void>;
};

export type WalletsApi = {
  readonly createWithPasskey: (options: {
    /** Display name for the new passkey credential (1–64 characters after trimming). */
    readonly name: string;
    readonly factor?: InitialFactor;
  }) => Promise<WalletInfo>;
  readonly restoreWithPasskey: (options?: {
    readonly factor?: InitialFactor;
  }) => Promise<WalletInfo>;
  readonly createMnemonic: (options: {
    readonly words: 12 | 24;
    readonly factor?: InitialFactor;
  }) => Promise<MnemonicDraft>;
  readonly importMnemonic: (options: {
    readonly mnemonic: string;
    readonly factor?: InitialFactor;
  }) => Promise<WalletInfo>;
  /** One-shot mnemonic export; requires re-verification every call. */
  readonly exportMnemonic: (walletId: string, verify: UnlockFactor) => Promise<ExportedSecret>;
  readonly delete: (walletId: string, verify: UnlockFactor) => Promise<void>;
};

export type DataKeyApi = {
  readonly get: (purpose: string) => Promise<Uint8Array>;
};

export type Wallet = {
  readonly getSnapshot: () => WalletSnapshot;
  readonly subscribe: (listener: () => void) => () => void;
  readonly vault: VaultApi;
  readonly wallets: WalletsApi;
  readonly dataKeys: DataKeyApi;
  readonly destroy: () => Promise<void>;
};
