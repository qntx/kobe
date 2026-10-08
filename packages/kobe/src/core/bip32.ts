import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { HDKey } from "@scure/bip32";

import { copyBytes, wipeBytes } from "./bytes.ts";
import { KobeError } from "./error.ts";

/** BIP-32 derived secp256k1 key material. */
export type DerivedSecp256k1Key = {
  /** Fresh 32-byte copy. @throws KobeError input if disposed */
  privateKeyBytes: () => Uint8Array;
  /** Footgun hex. @throws KobeError input if disposed */
  privateKeyHex: () => string;
  /** 33-byte SEC1 compressed public key. */
  compressedPublicKey: () => Uint8Array;
  /** 65-byte SEC1 uncompressed public key (`0x04` prefix). */
  uncompressedPublicKey: () => Uint8Array;
  compressedPublicKeyHex: () => string;
  uncompressedPublicKeyHex: () => string;
  dispose: () => void;
  toString: () => string;
};

class DerivedSecp256k1KeyImpl implements DerivedSecp256k1Key {
  #sk: Uint8Array | undefined;
  readonly #compressed: Uint8Array;
  readonly #uncompressed: Uint8Array;
  #disposed = false;

  constructor(sk: Uint8Array) {
    if (!secp256k1.utils.isValidSecretKey(sk)) {
      throw new KobeError("crypto", "secp256k1 scalar out of range or wrong length");
    }
    this.#sk = sk;
    this.#compressed = secp256k1.getPublicKey(sk, true);
    this.#uncompressed = secp256k1.getPublicKey(sk, false);
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
    if (this.#disposed) {
      return;
    }
    wipeBytes(this.#sk);
    this.#sk = undefined;
    this.#disposed = true;
  }

  toString(): string {
    return "DerivedSecp256k1Key [REDACTED]";
  }
}

/**
 * Derive a BIP-32 secp256k1 key at `path` from a 64-byte BIP-39 seed.
 *
 * Paths are strict: `m` or `m/…`, no trimming, no case folding. The private key is copied out of
 * the HDKey tree, then `wipePrivateData()` clears every intermediate key on both the child and the
 * root.
 *
 * @throws KobeError path | crypto
 */
export function deriveSecp256k1FromSeed(seed: Uint8Array, path: string): DerivedSecp256k1Key {
  if (seed.length < 16) {
    throw new KobeError("crypto", "seed too short for BIP-32");
  }
  if (path !== "m" && !path.startsWith("m/")) {
    throw new KobeError("path", "path must start with 'm/' or be exactly 'm'");
  }

  let root: HDKey;
  try {
    root = HDKey.fromMasterSeed(seed);
  } catch (error) {
    throw new KobeError(
      "crypto",
      error instanceof Error ? error.message : "BIP-32 master key failed",
      {
        cause: error,
      },
    );
  }

  let child: HDKey | undefined;
  try {
    child = path === "m" ? root : root.derive(path);
    if (!child.privateKey) {
      throw new KobeError("crypto", "derived key has no private key");
    }
    return new DerivedSecp256k1KeyImpl(copyBytes(child.privateKey));
  } catch (error) {
    if (error instanceof KobeError) {
      throw error;
    }
    throw new KobeError("path", error instanceof Error ? error.message : "BIP-32 derive failed", {
      cause: error,
    });
  } finally {
    child?.wipePrivateData();
    root.wipePrivateData();
  }
}
