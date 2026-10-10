import { bytesToHex } from "../crypto/hex.ts";
import { DeriveError } from "../errors/derive.ts";
import { copyBytes, wipeBytes } from "../secret/dispose.ts";

/**
 * Public-key payload. `bytes` is an owned snapshot captured at construction.
 * Survives `dispose()` of the parent account. Mutating `bytes` does not
 * affect the account; the library never mutates it after handoff.
 */
export type DerivedPublicKey =
  | { readonly kind: "secp256k1-compressed"; readonly bytes: Uint8Array }
  | { readonly kind: "secp256k1-uncompressed"; readonly bytes: Uint8Array }
  | { readonly kind: "ed25519"; readonly bytes: Uint8Array }
  | { readonly kind: "secp256k1-xonly"; readonly bytes: Uint8Array };

const KIND_LEN: Record<DerivedPublicKey["kind"], number> = {
  "secp256k1-compressed": 33,
  "secp256k1-uncompressed": 65,
  ed25519: 32,
  "secp256k1-xonly": 32,
};

/** Snapshot and validate a public-key payload. */
export function snapshotPublicKey(pk: DerivedPublicKey): DerivedPublicKey {
  const want = KIND_LEN[pk.kind];
  if (pk.bytes.length !== want) {
    throw new DeriveError(
      "crypto",
      `${pk.kind} public key requires ${want} bytes, got ${pk.bytes.length}`,
    );
  }
  return { kind: pk.kind, bytes: copyBytes(pk.bytes) };
}

export interface DerivedAccount {
  readonly path: string;
  readonly publicKey: DerivedPublicKey;
  readonly address: string;

  /** Fresh 32-byte copy. @throws DeriveError input if disposed */
  privateKeyBytes(): Uint8Array;
  /** Footgun hex. @throws if disposed */
  privateKeyHex(): string;
  publicKeyBytes(): Uint8Array;
  publicKeyHex(): string;
  dispose(): void;
  [Symbol.dispose](): void;
  toString(): string;
}

/** SVM wrapper type (construction in PR9). */
export interface SvmAccount extends DerivedAccount {
  /** Base58(secret‖public) Phantom format. @throws if disposed */
  keypairBase58(): string;
}

export interface CreateDerivedAccountInput {
  path: string;
  privateKey: Uint8Array;
  publicKey: DerivedPublicKey;
  address: string;
}

/**
 * Build a `DerivedAccount`. Copies the 32-byte secret; snapshots pubkey bytes.
 * @throws DeriveError crypto if secret is not 32 bytes or pubkey length mismatches
 */
export function createDerivedAccount(input: CreateDerivedAccountInput): DerivedAccount {
  if (input.privateKey.length !== 32) {
    throw new DeriveError(
      "crypto",
      `private key requires 32 bytes, got ${input.privateKey.length}`,
    );
  }
  return new DerivedAccountImpl(
    input.path,
    copyBytes(input.privateKey),
    snapshotPublicKey(input.publicKey),
    input.address,
  );
}

class DerivedAccountImpl implements DerivedAccount {
  readonly path: string;
  readonly publicKey: DerivedPublicKey;
  readonly address: string;

  #sk: Uint8Array | undefined;
  #disposed = false;

  constructor(path: string, sk: Uint8Array, publicKey: DerivedPublicKey, address: string) {
    this.path = path;
    this.#sk = sk;
    this.publicKey = publicKey;
    this.address = address;
  }

  #assertLive(): void {
    if (this.#disposed || !this.#sk) {
      throw new DeriveError("input", "disposed");
    }
  }

  privateKeyBytes(): Uint8Array {
    this.#assertLive();
    return copyBytes(this.#sk!);
  }

  privateKeyHex(): string {
    return bytesToHex(this.privateKeyBytes());
  }

  publicKeyBytes(): Uint8Array {
    return copyBytes(this.publicKey.bytes);
  }

  publicKeyHex(): string {
    return bytesToHex(this.publicKey.bytes);
  }

  dispose(): void {
    if (this.#disposed) return;
    wipeBytes(this.#sk);
    this.#sk = undefined;
    this.#disposed = true;
  }

  [Symbol.dispose](): void {
    this.dispose();
  }

  toString(): string {
    return `DerivedAccount { path: ${this.path}, address: ${this.address}, privateKey: [REDACTED] }`;
  }

  toJSON(): {
    path: string;
    address: string;
    publicKey: { kind: string; bytes: string };
    privateKey: string;
  } {
    return {
      path: this.path,
      address: this.address,
      publicKey: {
        kind: this.publicKey.kind,
        bytes: bytesToHex(this.publicKey.bytes),
      },
      privateKey: "[REDACTED]",
    };
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return this.toString();
  }
}
