import {
  isValidSecp256k1Secret,
  secp256k1PublicKey,
  secp256k1SignPrehash,
  secp256k1SignPrehashDer,
  secp256k1VerifyPrehash,
  secp256k1VerifyPrehashDer,
} from "../../ecc/secp256k1.ts";
import { SignError } from "../../errors/sign.ts";
import { wipeBytes } from "../../secret/dispose.ts";
import type { SecretKey32 } from "../../secret/secret-key32.ts";
import type { SignOutput } from "../output.ts";
import type { SignDigest } from "../traits.ts";

export type EcdsaRecoverableOutput = Extract<SignOutput, { scheme: "ecdsa_recoverable" }>;
export type EcdsaDerOutput = Extract<SignOutput, { scheme: "ecdsa_der" }>;

export interface Secp256k1Signer extends SignDigest {
  signPrehashRecoverable(digest: Uint8Array): EcdsaRecoverableOutput;
  signPrehashDer(digest: Uint8Array): EcdsaDerOutput;
  verifyPrehash(digest: Uint8Array, signature: Uint8Array): boolean;
  verifyPrehashDer(digest: Uint8Array, signatureDer: Uint8Array): boolean;
  compressedPublicKey(): Uint8Array;
  uncompressedPublicKey(): Uint8Array;
  dispose(): void;
  [Symbol.dispose](): void;
}

class Secp256k1SignerImpl implements Secp256k1Signer {
  #sk: Uint8Array | undefined;
  #compressed: Uint8Array;
  #uncompressed: Uint8Array;
  #disposed = false;

  constructor(sk: Uint8Array) {
    this.#sk = sk;
    this.#compressed = secp256k1PublicKey(sk, true);
    this.#uncompressed = secp256k1PublicKey(sk, false);
  }

  #assertLive(): Uint8Array {
    if (this.#disposed || !this.#sk) {
      throw new SignError("invalid_key", "disposed");
    }
    return this.#sk;
  }

  signPrehashRecoverable(digest: Uint8Array): EcdsaRecoverableOutput {
    const { signature, recovery } = secp256k1SignPrehash(this.#assertLive(), digest);
    return { scheme: "ecdsa_recoverable", signature, v: recovery };
  }

  signPrehashDer(digest: Uint8Array): EcdsaDerOutput {
    return { scheme: "ecdsa_der", der: secp256k1SignPrehashDer(this.#assertLive(), digest) };
  }

  signDigest(digest: Uint8Array): EcdsaRecoverableOutput {
    return this.signPrehashRecoverable(digest);
  }

  verifyPrehash(digest: Uint8Array, signature: Uint8Array): boolean {
    return secp256k1VerifyPrehash(this.#compressed, digest, signature);
  }

  verifyPrehashDer(digest: Uint8Array, signatureDer: Uint8Array): boolean {
    return secp256k1VerifyPrehashDer(this.#compressed, digest, signatureDer);
  }

  compressedPublicKey(): Uint8Array {
    return new Uint8Array(this.#compressed);
  }

  uncompressedPublicKey(): Uint8Array {
    return new Uint8Array(this.#uncompressed);
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
}

/**
 * @throws SignError invalid_key if scalar is 0 or ≥ curve order, or key disposed.
 * Copies key material into signer-owned storage.
 */
export function secp256k1SignerFromSecret(key: SecretKey32): Secp256k1Signer {
  const bytes = key.toBytes();
  try {
    if (!isValidSecp256k1Secret(bytes)) {
      throw new SignError("invalid_key", "secp256k1 scalar out of range or wrong length");
    }
    return new Secp256k1SignerImpl(bytes);
  } catch (e) {
    wipeBytes(bytes);
    throw e;
  }
}
