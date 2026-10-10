import { copyBytes, wipeBytes } from "./bytes.ts";
import { KobeError } from "./error.ts";

/**
 * Opaque 32-byte secret key shared by the curve signers.
 *
 * Bytes are never exposed through `toString` / `toJSON`; the only view is {@link SecretKey.toBytes},
 * which hands out a fresh copy the caller owns (and should wipe if retained).
 */
export class SecretKey {
  #bytes: Uint8Array | undefined;
  #disposed = false;

  private constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  #live(): Uint8Array {
    const bytes = this.#bytes;
    if (this.#disposed || !bytes) {
      throw new KobeError("input", "disposed");
    }
    return bytes;
  }

  /**
   * Wrap raw secret bytes (copied).
   *
   * @throws KobeError input if `bytes` is not exactly 32 bytes
   */
  static fromBytes(bytes: Uint8Array): SecretKey {
    if (bytes.length !== 32) {
      throw new KobeError("input", `expected 32-byte secret key, got ${bytes.length} bytes`);
    }
    return new SecretKey(copyBytes(bytes));
  }

  /** Copy the 32-byte private key of a derived HD account. */
  static fromAccount(account: { privateKeyBytes: () => Uint8Array }): SecretKey {
    const bytes = account.privateKeyBytes();
    try {
      return SecretKey.fromBytes(bytes);
    } finally {
      wipeBytes(bytes);
    }
  }

  /**
   * Fresh 32-byte copy. The caller owns it and should wipe it if retained.
   *
   * @throws KobeError input if disposed
   */
  toBytes(): Uint8Array {
    return copyBytes(this.#live());
  }

  dispose(): void {
    if (this.#disposed) {
      return;
    }
    wipeBytes(this.#bytes);
    this.#bytes = undefined;
    this.#disposed = true;
  }

  toString(): string {
    return "SecretKey([REDACTED])";
  }

  toJSON(): string {
    return "SecretKey([REDACTED])";
  }
}
