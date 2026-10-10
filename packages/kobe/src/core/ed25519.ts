import { ed25519 } from "@noble/curves/ed25519.js";

import { copyBytes, wipeBytes } from "./bytes.ts";
import { KobeError } from "./error.ts";
import type { SecretKey } from "./secret.ts";

/**
 * Ed25519 signer: deterministic RFC 8032 signing. Every 32-byte string is a valid seed.
 *
 * The secret is copied into signer-owned storage and wiped on {@link Ed25519Signer.dispose}.
 */
export class Ed25519Signer {
  #sk: Uint8Array | undefined;
  readonly #pk: Uint8Array;
  #disposed = false;

  private constructor(sk: Uint8Array) {
    this.#sk = sk;
    this.#pk = ed25519.getPublicKey(sk);
  }

  /**
   * Create from a 32-byte secret seed (copied). Infallible: every 32-byte string is a valid Ed25519
   * seed.
   *
   * @throws KobeError input if `secret` is disposed
   */
  static fromSecretKey(secret: SecretKey): Ed25519Signer {
    const bytes = secret.toBytes();
    try {
      return new Ed25519Signer(bytes);
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

  /** 32-byte public key (fresh copy). */
  publicKey(): Uint8Array {
    return copyBytes(this.#pk);
  }

  /**
   * Sign arbitrary bytes with raw Ed25519 (no prefix or hashing).
   *
   * @throws KobeError input if the signer is disposed; crypto on primitive failure
   */
  sign(message: Uint8Array): Uint8Array {
    try {
      return ed25519.sign(message, this.#live());
    } catch (error) {
      throw new KobeError(
        "crypto",
        error instanceof Error ? error.message : "ed25519 sign failed",
        { cause: error },
      );
    }
  }

  /**
   * Verify a 64-byte Ed25519 signature against `message`. Malformed input returns `false`; never
   * throws.
   */
  verify(message: Uint8Array, signature: Uint8Array): boolean {
    if (signature.length !== 64) {
      return false;
    }
    try {
      return ed25519.verify(signature, message, this.#pk);
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
