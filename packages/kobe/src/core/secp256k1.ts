import { secp256k1 } from "@noble/curves/secp256k1.js";

import { copyBytes, wipeBytes } from "./bytes.ts";
import { KobeError } from "./error.ts";
import type { SecretKey } from "./secret.ts";
import type { RecoverableSignature } from "./signature.ts";

/**
 * Secp256k1 ECDSA signer: RFC 6979 deterministic, low-S signatures over a 32-byte pre-hashed
 * digest.
 *
 * The secret is copied into signer-owned storage and wiped on {@link Secp256k1Signer.dispose}.
 */
export class Secp256k1Signer {
  #sk: Uint8Array | undefined;
  readonly #compressed: Uint8Array;
  readonly #uncompressed: Uint8Array;
  #disposed = false;

  private constructor(sk: Uint8Array) {
    this.#sk = sk;
    this.#compressed = secp256k1.getPublicKey(sk, true);
    this.#uncompressed = secp256k1.getPublicKey(sk, false);
  }

  /**
   * Create from a 32-byte secret (copied).
   *
   * @throws KobeError crypto if the scalar is zero or ≥ the curve order; input if `secret` is
   *   disposed
   */
  static fromSecretKey(secret: SecretKey): Secp256k1Signer {
    const bytes = secret.toBytes();
    try {
      if (!secp256k1.utils.isValidSecretKey(bytes)) {
        throw new KobeError("crypto", "secp256k1 scalar out of range or wrong length");
      }
      return new Secp256k1Signer(bytes);
    } catch (error) {
      wipeBytes(bytes);
      throw error;
    }
  }

  #live(): Uint8Array {
    const sk = this.#sk;
    if (this.#disposed || !sk) {
      throw new KobeError("input", "disposed");
    }
    return sk;
  }

  /** 33-byte SEC1 compressed public key (fresh copy). */
  compressedPublicKey(): Uint8Array {
    return copyBytes(this.#compressed);
  }

  /** 65-byte SEC1 uncompressed public key (`0x04` prefix; fresh copy). */
  uncompressedPublicKey(): Uint8Array {
    return copyBytes(this.#uncompressed);
  }

  /**
   * Sign a 32-byte pre-hashed digest, returning `r || s` plus the raw recovery parity (`0` or `1`).
   * Deterministic (RFC 6979) and normalized to low-S.
   *
   * @throws KobeError input if `digest` is not 32 bytes or the signer is disposed; crypto on
   *   primitive failure
   */
  signRecoverable(digest: Uint8Array): RecoverableSignature {
    if (digest.length !== 32) {
      throw new KobeError("input", "digest must be 32 bytes");
    }
    let recovered: Uint8Array;
    try {
      recovered = secp256k1.sign(digest, this.#live(), { prehash: false, format: "recovered" });
    } catch (error) {
      throw new KobeError(
        "crypto",
        error instanceof Error ? error.message : "secp256k1 sign failed",
        { cause: error },
      );
    }
    const [recovery] = recovered;
    if (recovery !== 0 && recovery !== 1) {
      throw new KobeError("crypto", `unexpected recovery id ${String(recovery)}`);
    }
    return { signature: copyBytes(recovered.subarray(1)), recovery };
  }

  /**
   * Sign a 32-byte pre-hashed digest, returning the ASN.1 DER encoding (typically 70–72 bytes). No
   * recovery id.
   *
   * @throws KobeError input if `digest` is not 32 bytes or the signer is disposed; crypto on
   *   primitive failure
   */
  signDer(digest: Uint8Array): Uint8Array {
    if (digest.length !== 32) {
      throw new KobeError("input", "digest must be 32 bytes");
    }
    try {
      return secp256k1.sign(digest, this.#live(), { prehash: false, format: "der" });
    } catch (error) {
      throw new KobeError(
        "crypto",
        error instanceof Error ? error.message : "secp256k1 DER sign failed",
        { cause: error },
      );
    }
  }

  /**
   * Verify a compact (64-byte) or recoverable (65-byte) ECDSA signature against a 32-byte
   * pre-hashed digest. The trailing `v` byte of a 65-byte signature is ignored. Malformed input
   * returns `false`; never throws.
   */
  verify(digest: Uint8Array, signature: Uint8Array): boolean {
    if (digest.length !== 32) {
      return false;
    }
    const compact =
      signature.length === 64
        ? signature
        : signature.length === 65
          ? signature.subarray(0, 64)
          : undefined;
    if (!compact) {
      return false;
    }
    try {
      return secp256k1.verify(compact, digest, this.#compressed, { prehash: false });
    } catch {
      return false;
    }
  }

  dispose(): void {
    if (this.#disposed) {
      return;
    }
    wipeBytes(this.#sk);
    this.#sk = undefined;
    this.#disposed = true;
  }
}
