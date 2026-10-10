import { HDKey } from "@scure/bip32";
import { bytesToHex } from "../crypto/hex.ts";
import { secp256k1PublicKey } from "../ecc/secp256k1.ts";
import { DeriveError } from "../errors/derive.ts";
import { copyBytes, wipeBytes } from "../secret/dispose.ts";

/** BIP-32 derived secp256k1 key material. */
export interface DerivedSecp256k1Key {
  privateKeyBytes(): Uint8Array;
  privateKeyHex(): string;
  compressedPublicKey(): Uint8Array;
  uncompressedPublicKey(): Uint8Array;
  compressedPublicKeyHex(): string;
  uncompressedPublicKeyHex(): string;
  dispose(): void;
  [Symbol.dispose](): void;
  toString(): string;
}

class DerivedSecp256k1KeyImpl implements DerivedSecp256k1Key {
  #sk: Uint8Array | undefined;
  #compressed: Uint8Array;
  #uncompressed: Uint8Array;
  #disposed = false;

  constructor(sk: Uint8Array) {
    this.#sk = sk;
    this.#compressed = secp256k1PublicKey(sk, true);
    this.#uncompressed = secp256k1PublicKey(sk, false);
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

  compressedPublicKey(): Uint8Array {
    return copyBytes(this.#compressed);
  }

  uncompressedPublicKey(): Uint8Array {
    return copyBytes(this.#uncompressed);
  }

  compressedPublicKeyHex(): string {
    return bytesToHex(this.#compressed);
  }

  uncompressedPublicKeyHex(): string {
    return bytesToHex(this.#uncompressed);
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
    return "DerivedSecp256k1Key [REDACTED]";
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return this.toString();
  }
}

/**
 * Derive BIP-32 secp256k1 key at path from BIP-39 seed (64 bytes).
 * @throws DeriveError path | crypto
 */
export function deriveSecp256k1FromSeed(seed: Uint8Array, path: string): DerivedSecp256k1Key {
  if (seed.length < 16) {
    throw new DeriveError("crypto", "seed too short for BIP-32");
  }
  const trimmed = path.trim();
  if (trimmed !== "m" && !trimmed.startsWith("m/")) {
    throw new DeriveError("path", "path must start with 'm/' or be exactly 'm'");
  }
  try {
    const root = HDKey.fromMasterSeed(seed);
    const child = trimmed === "m" ? root : root.derive(trimmed);
    if (!child.privateKey) {
      throw new DeriveError("crypto", "derived key has no private key");
    }
    return new DerivedSecp256k1KeyImpl(copyBytes(child.privateKey));
  } catch (e) {
    if (e instanceof DeriveError) throw e;
    throw new DeriveError("path", e instanceof Error ? e.message : "BIP-32 derive failed", {
      cause: e,
    });
  }
}
