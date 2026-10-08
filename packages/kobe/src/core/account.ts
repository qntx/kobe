import { bytesToHex } from "@noble/hashes/utils.js";

import { copyBytes, wipeBytes } from "./bytes.ts";
import { KobeError } from "./error.ts";

/**
 * Public-key payload. `kind` strings are exactly `PublicKeyKind::as_str()` in kobe-core. `bytes` is
 * an owned snapshot captured at construction; it survives `dispose()` of the parent account and
 * mutating it does not affect the account.
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
function snapshotPublicKey(pk: DerivedPublicKey): DerivedPublicKey {
  const want = KIND_LEN[pk.kind];
  if (pk.bytes.length !== want) {
    throw new KobeError(
      "crypto",
      `${pk.kind} public key requires ${want} bytes, got ${pk.bytes.length}`,
    );
  }
  return { kind: pk.kind, bytes: copyBytes(pk.bytes) };
}

/** A derived HD account — unified across all chains. */
export type DerivedAccount = {
  readonly path: string;
  readonly publicKey: DerivedPublicKey;
  readonly address: string;

  /** Fresh 32-byte copy. @throws KobeError input if disposed */
  privateKeyBytes: () => Uint8Array;
  /** Footgun hex. @throws KobeError input if disposed */
  privateKeyHex: () => string;
  publicKeyBytes: () => Uint8Array;
  publicKeyHex: () => string;
  dispose: () => void;
  toString: () => string;
};

export type CreateDerivedAccountInput = {
  path: string;
  privateKey: Uint8Array;
  publicKey: DerivedPublicKey;
  address: string;
};

/**
 * Build a `DerivedAccount`. Copies the 32-byte secret; snapshots pubkey bytes.
 *
 * Internal module export — not re-exported from the package index; chain modules call this after
 * completing their derivation pipeline.
 *
 * @throws KobeError crypto if the secret is not 32 bytes or the public key length mismatches its
 *   kind
 */
export function createDerivedAccount(input: CreateDerivedAccountInput): DerivedAccount {
  if (input.privateKey.length !== 32) {
    throw new KobeError("crypto", `private key requires 32 bytes, got ${input.privateKey.length}`);
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

  #live(): Uint8Array {
    const sk = this.#sk;
    if (this.#disposed || !sk) {
      throw new KobeError("input", "disposed");
    }
    return sk;
  }

  privateKeyBytes(): Uint8Array {
    return copyBytes(this.#live());
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
    if (this.#disposed) {
      return;
    }
    wipeBytes(this.#sk);
    this.#sk = undefined;
    this.#disposed = true;
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
}
