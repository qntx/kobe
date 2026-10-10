import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";

import { copyBytes, wipeBytes } from "./bytes.ts";
import { KobeError } from "./error.ts";
import type { SecretKey } from "./secret.ts";

/**
 * BIP-340 Schnorr signer over secp256k1 (Taproot / NIP-01 style).
 *
 * Signing and verifying operate on the raw message bytes — no implicit hashing, so arbitrary-length
 * messages are allowed. The secret is copied into signer-owned storage and wiped on
 * {@link SchnorrSigner.dispose}.
 */
export class SchnorrSigner {
  #sk: Uint8Array | undefined;
  readonly #xonly: Uint8Array;
  #disposed = false;

  private constructor(sk: Uint8Array) {
    this.#sk = sk;
    this.#xonly = schnorr.getPublicKey(sk);
  }

  /**
   * Create from a 32-byte secret (copied).
   *
   * @throws KobeError crypto if the scalar is zero or ≥ the curve order; input if `secret` is
   *   disposed
   */
  static fromSecretKey(secret: SecretKey): SchnorrSigner {
    const bytes = secret.toBytes();
    try {
      if (!secp256k1.utils.isValidSecretKey(bytes)) {
        throw new KobeError("crypto", "secp256k1 scalar out of range or wrong length");
      }
      return new SchnorrSigner(bytes);
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

  /** 32-byte BIP-340 x-only public key (fresh copy). */
  xonlyPublicKey(): Uint8Array {
    return copyBytes(this.#xonly);
  }

  /**
   * Sign `message` bytes directly with BIP-340 Schnorr. The message is used verbatim as the `m`
   * input — no implicit SHA-256 is applied. `auxRand` is the caller-supplied BIP-340 auxiliary
   * randomness (a 32-byte all-zero buffer gives deterministic output); when omitted, noble samples
   * random auxiliary bytes.
   *
   * @throws KobeError input if the signer is disposed; crypto on primitive failure
   */
  sign(message: Uint8Array, auxRand?: Uint8Array): Uint8Array {
    try {
      return schnorr.sign(message, this.#live(), auxRand);
    } catch (error) {
      throw new KobeError(
        "crypto",
        error instanceof Error ? error.message : "schnorr sign failed",
        { cause: error },
      );
    }
  }

  /**
   * Verify a 64-byte BIP-340 Schnorr signature against `message`. Malformed input returns `false`;
   * never throws.
   */
  verify(message: Uint8Array, signature: Uint8Array): boolean {
    return SchnorrSigner.verifyWith(this.#xonly, message, signature);
  }

  /**
   * Verify a BIP-340 signature under an arbitrary x-only public key. Malformed public key or
   * signature returns `false`; never throws.
   */
  static verifyWith(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
    if (publicKey.length !== 32 || signature.length !== 64) {
      return false;
    }
    try {
      return schnorr.verify(signature, message, publicKey);
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
