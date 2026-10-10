import { ed25519PublicKey, ed25519Sign, ed25519Verify } from "../../ecc/ed25519.ts";
import { SignError } from "../../errors/sign.ts";
import { wipeBytes } from "../../secret/dispose.ts";
import type { SecretKey32 } from "../../secret/secret-key32.ts";
import type { SignOutput } from "../output.ts";
import type { SignDigest, SignMessage } from "../traits.ts";

export type Ed25519Output = Extract<SignOutput, { scheme: "ed25519" }>;

export type Ed25519Signer = {
  sign(message: Uint8Array): Ed25519Output;
  verify(message: Uint8Array, signature: Uint8Array): boolean;
  publicKey(): Uint8Array;
  dispose(): void;
  [Symbol.dispose](): void;
} & SignDigest &
  SignMessage;

class Ed25519SignerImpl implements Ed25519Signer {
  #sk: Uint8Array | undefined;
  readonly #pk: Uint8Array;
  #disposed = false;

  constructor(sk: Uint8Array) {
    this.#sk = sk;
    this.#pk = ed25519PublicKey(sk);
  }

  #assertLive(): Uint8Array {
    if (this.#disposed || !this.#sk) {
      throw new SignError("invalid_key", "disposed");
    }
    return this.#sk;
  }

  sign(message: Uint8Array): Ed25519Output {
    const signature = ed25519Sign(this.#assertLive(), message);
    return { scheme: "ed25519", signature };
  }

  signMessage(message: Uint8Array): Ed25519Output {
    return this.sign(message);
  }

  signDigest(digest: Uint8Array): Ed25519Output {
    if (digest.length !== 32) {
      throw new SignError("invalid_message", "digest must be 32 bytes");
    }
    return this.sign(digest);
  }

  verify(message: Uint8Array, signature: Uint8Array): boolean {
    return ed25519Verify(this.#pk, message, signature);
  }

  publicKey(): Uint8Array {
    return new Uint8Array(this.#pk);
  }

  dispose(): void {
    if (this.#disposed) {
      return;
    }
    wipeBytes(this.#sk);
    this.#sk = undefined;
    this.#disposed = true;
  }

  [Symbol.dispose](): void {
    this.dispose();
  }
}

/**
 * Ed25519: every 32-byte seed is valid. Copies into signer-owned storage.
 *
 * @throws SignError invalid_key if SecretKey32 is disposed
 */
export function ed25519SignerFromSecret(key: SecretKey32): Ed25519Signer {
  const bytes = key.toBytes();
  try {
    return new Ed25519SignerImpl(bytes);
  } catch (error) {
    wipeBytes(bytes);
    throw error;
  }
}
