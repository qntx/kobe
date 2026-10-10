import { schnorr } from "@noble/curves/secp256k1.js";

import { isValidSecp256k1Secret } from "../../ecc/secp256k1.ts";
import { SignError } from "../../errors/sign.ts";
import { wipeBytes } from "../../secret/dispose.ts";
import type { SecretKey32 } from "../../secret/secret-key32.ts";
import type { SignOutput } from "../output.ts";
import type { SignDigest, SignMessage } from "../traits.ts";

export type SchnorrOutput = Extract<SignOutput, { scheme: "schnorr" }>;

export type SchnorrSigner = {
  sign(message: Uint8Array): SchnorrOutput;
  signPrehash(digest: Uint8Array): SchnorrOutput;
  verify(message: Uint8Array, signature: Uint8Array): boolean;
  xonlyPublicKey(): Uint8Array;
  dispose(): void;
  [Symbol.dispose](): void;
} & SignDigest &
  SignMessage;

const ZERO_AUX = new Uint8Array(32);

class SchnorrSignerImpl implements SchnorrSigner {
  #sk: Uint8Array | undefined;
  readonly #xonly: Uint8Array;
  #disposed = false;

  constructor(sk: Uint8Array) {
    this.#sk = sk;
    this.#xonly = schnorr.getPublicKey(sk);
  }

  #assertLive(): Uint8Array {
    if (this.#disposed || !this.#sk) {
      throw new SignError("invalid_key", "disposed");
    }
    return this.#sk;
  }

  sign(message: Uint8Array): SchnorrOutput {
    try {
      const signature = schnorr.sign(message, this.#assertLive(), ZERO_AUX);
      return {
        scheme: "schnorr",
        signature,
        xonlyPublicKey: new Uint8Array(this.#xonly),
      };
    } catch (error) {
      if (error instanceof SignError) {
        throw error;
      }
      throw new SignError(
        "signing_failed",
        error instanceof Error ? error.message : "schnorr sign failed",
        { cause: error },
      );
    }
  }

  signPrehash(digest: Uint8Array): SchnorrOutput {
    if (digest.length !== 32) {
      throw new SignError("invalid_message", "digest must be 32 bytes");
    }
    return this.sign(digest);
  }

  signDigest(digest: Uint8Array): SchnorrOutput {
    return this.signPrehash(digest);
  }

  signMessage(message: Uint8Array): SchnorrOutput {
    return this.sign(message);
  }

  verify(message: Uint8Array, signature: Uint8Array): boolean {
    if (signature.length !== 64) {
      throw new SignError("invalid_signature", "schnorr signature must be 64 bytes");
    }
    try {
      return schnorr.verify(signature, message, this.#xonly);
    } catch (error) {
      throw new SignError(
        "invalid_signature",
        error instanceof Error ? error.message : "malformed signature",
        { cause: error },
      );
    }
  }

  xonlyPublicKey(): Uint8Array {
    return new Uint8Array(this.#xonly);
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

export function schnorrSignerFromSecret(key: SecretKey32): SchnorrSigner {
  const bytes = key.toBytes();
  try {
    if (!isValidSecp256k1Secret(bytes)) {
      throw new SignError("invalid_key", "secp256k1 scalar out of range or wrong length");
    }
    return new SchnorrSignerImpl(bytes);
  } catch (error) {
    wipeBytes(bytes);
    throw error;
  }
}
