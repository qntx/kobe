import { hexToBytes } from "../crypto/hex.ts";
import { SignError } from "../errors/sign.ts";
import { copyBytes, wipeBytes } from "./dispose.ts";

/** Structural account view — avoids a runtime HD import. */
export type DerivedSecretSource = {
  privateKeyBytes(): Uint8Array;
};

/** Opaque 32-byte secret. No public `bytes` field. inspect / toJSON → `SecretKey32([REDACTED])`. */
export type SecretKey32 = {
  /** Fresh 32-byte copy. Caller owns and should wipe if retained. */
  toBytes(): Uint8Array;
  clone(): SecretKey32;
  dispose(): void;
  [Symbol.dispose](): void;
  toString(): string;
};

class SecretKey32Impl implements SecretKey32 {
  #bytes: Uint8Array | undefined;
  #disposed = false;

  constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  #live(): Uint8Array {
    const bytes = this.#bytes;
    if (this.#disposed || bytes === undefined) {
      throw new SignError("invalid_key", "disposed");
    }
    return bytes;
  }

  toBytes(): Uint8Array {
    return copyBytes(this.#live());
  }

  clone(): SecretKey32 {
    return secretKeyFromBytes(this.toBytes());
  }

  dispose(): void {
    if (this.#disposed) {
      return;
    }
    wipeBytes(this.#bytes);
    this.#bytes = undefined;
    this.#disposed = true;
  }

  [Symbol.dispose](): void {
    this.dispose();
  }

  toString(): string {
    return "SecretKey32([REDACTED])";
  }

  toJSON(): string {
    return "SecretKey32([REDACTED])";
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return this.toString();
  }
}

/** @throws SignError invalid_key if length !== 32 */
export function secretKeyFromBytes(bytes: Uint8Array): SecretKey32 {
  if (bytes.length !== 32) {
    throw new SignError("invalid_key", `secret must be 32 bytes, got ${bytes.length}`);
  }
  return new SecretKey32Impl(copyBytes(bytes));
}

/** @throws SignError invalid_key on bad hex/length */
export function secretKeyFromHex(hex: string): SecretKey32 {
  let bytes: Uint8Array;
  try {
    bytes = hexToBytes(hex);
  } catch (error) {
    throw new SignError("invalid_key", error instanceof Error ? error.message : "invalid hex", {
      cause: error,
    });
  }
  return secretKeyFromBytes(bytes);
}

/** Copies `account.privateKeyBytes()` into a new SecretKey32. */
export function secretKeyFromDerived(account: DerivedSecretSource): SecretKey32 {
  const sk = account.privateKeyBytes();
  try {
    return secretKeyFromBytes(sk);
  } finally {
    wipeBytes(sk);
  }
}
