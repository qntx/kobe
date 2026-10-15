/**
 * A record kind names the module that owns the record's header and plaintext format. The store and
 * the envelope are kind-agnostic: any string matching the pattern is a valid kind, and a stored
 * kind no module claims marks the vault corrupted rather than being dropped.
 */
const RECORD_KIND_PATTERN = /^[a-z][a-z0-9-]{0,31}$/;

/** Whether `kind` is a well-formed record kind (lowercase, 1–32 characters). */
export function isRecordKind(kind: string): boolean {
  return RECORD_KIND_PATTERN.test(kind);
}

/** On-disk vault shapes. `header` is the raw JSON text, authenticated as-is. */
export type StoredRecord = {
  readonly kind: string; // see isRecordKind
  readonly id: string;
  readonly header: string;
  readonly sealed: Uint8Array;
};

export type StoredFactor = {
  readonly kind: "password" | "passkey";
  readonly id: string; // hex of 16 random bytes
  readonly header: string;
  readonly sealed: Uint8Array; // wrapped DEK
};

export type VaultMeta = {
  readonly format: 1;
  readonly failedAttempts: number;
  readonly retryAt: number; // epoch ms; 0 means no wait required
};

export type VaultImage = {
  readonly meta: VaultMeta | undefined; // undefined means uninitialized
  readonly records: ReadonlyArray<StoredRecord>;
  readonly factors: ReadonlyArray<StoredFactor>;
};

export type StoreOp =
  | { readonly op: "expect-uninitialized" } // precondition, checked inside the transaction
  | { readonly op: "put-meta"; readonly meta: VaultMeta }
  | { readonly op: "put-record"; readonly record: StoredRecord }
  | { readonly op: "delete-record"; readonly kind: StoredRecord["kind"]; readonly id: string }
  | { readonly op: "put-factor"; readonly factor: StoredFactor }
  | { readonly op: "delete-factor"; readonly id: string }
  | { readonly op: "clear" };

export type RecordStore = {
  load: () => Promise<VaultImage>;
  /** Atomic. A failed precondition rejects without writing anything. */
  commit: (ops: ReadonlyArray<StoreOp>) => Promise<void>;
  /** Fires after every commit (other tabs on Web trigger it via the host). */
  watch: (listener: () => void) => () => void;
};
