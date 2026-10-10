import { base58 } from "@scure/base";

import { bytesToHex } from "../../crypto/hex.ts";
import { SignError } from "../../errors/sign.ts";
import { wipeBytes } from "../../secret/dispose.ts";
import { ed25519SignerFromSecret, signerFromSecret } from "../../sign/index.ts";
import type { Ed25519Signer, SecretKey32, SignerKit, SignOutput } from "../../sign/index.ts";
import { extractSignableBytes, spliceSignature } from "./compact-u16.ts";

export type SvmSigner = {
  address(): string;
  publicKeyBytes(): Uint8Array;
  publicKeyHex(): string;
  keypairBase58(): string;
  signDigest(digest: Uint8Array): SignOutput;
  signMessage(message: Uint8Array): SignOutput;
  signTransaction(txMessage: Uint8Array): SignOutput;
  extractSignableBytes(txBytes: Uint8Array): Uint8Array;
  encodeSignedTransaction(txBytes: Uint8Array, signature: SignOutput): Uint8Array;
  spliceSignature(txBytes: Uint8Array, signature: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array): boolean;
  dispose(): void;
  [Symbol.dispose](): void;
};

class SvmSignerImpl implements SvmSigner {
  readonly #inner: Ed25519Signer;
  readonly #sk: Uint8Array;
  #disposed = false;

  constructor(inner: Ed25519Signer, sk: Uint8Array) {
    this.#inner = inner;
    this.#sk = sk;
  }

  #assertLive(): void {
    if (this.#disposed) {
      throw new SignError("invalid_key", "disposed");
    }
  }

  address(): string {
    this.#assertLive();
    return base58.encode(this.#inner.publicKey());
  }

  publicKeyBytes(): Uint8Array {
    return this.#inner.publicKey();
  }

  publicKeyHex(): string {
    return bytesToHex(this.publicKeyBytes());
  }

  keypairBase58(): string {
    this.#assertLive();
    const buf = new Uint8Array(64);
    buf.set(this.#sk, 0);
    buf.set(this.#inner.publicKey(), 32);
    const encoded = base58.encode(buf);
    wipeBytes(buf);
    return encoded;
  }

  signDigest(digest: Uint8Array): SignOutput {
    this.#assertLive();
    return this.#inner.signDigest(digest);
  }

  signMessage(message: Uint8Array): SignOutput {
    this.#assertLive();
    return this.#inner.sign(message);
  }

  signTransaction(txMessage: Uint8Array): SignOutput {
    this.#assertLive();
    return this.#inner.sign(txMessage);
  }

  extractSignableBytes(txBytes: Uint8Array): Uint8Array {
    return extractSignableBytes(txBytes);
  }

  encodeSignedTransaction(txBytes: Uint8Array, signature: SignOutput): Uint8Array {
    const sig =
      signature.scheme === "ed25519" || signature.scheme === "ed25519_with_pubkey"
        ? signature.signature
        : undefined;
    if (!sig) {
      throw new SignError("invalid_signature", "expected Ed25519 signature output");
    }
    return spliceSignature(txBytes, sig);
  }

  spliceSignature(txBytes: Uint8Array, signature: Uint8Array): Uint8Array {
    return spliceSignature(txBytes, signature);
  }

  verify(message: Uint8Array, signature: Uint8Array): boolean {
    return this.#inner.verify(message, signature);
  }

  dispose(): void {
    if (this.#disposed) {
      return;
    }
    wipeBytes(this.#sk);
    this.#inner.dispose();
    this.#disposed = true;
  }

  [Symbol.dispose](): void {
    this.dispose();
  }
}

function svmSignerFromSecretKey(key: SecretKey32): SvmSigner {
  const sk = key.toBytes();
  return new SvmSignerImpl(ed25519SignerFromSecret(key), sk);
}

const svmSignerKit = signerFromSecret(svmSignerFromSecretKey);

function svmSignerFromKeypairBase58(b58: string): SvmSigner {
  let decoded: Uint8Array;
  try {
    decoded = base58.decode(b58);
  } catch (error) {
    throw new SignError(
      "invalid_key",
      error instanceof Error ? `keypair base58: ${error.message}` : "keypair base58",
      { cause: error },
    );
  }
  if (decoded.length !== 64) {
    throw new SignError("invalid_key", `keypair: expected 64 bytes, got ${decoded.length}`);
  }
  const secret = decoded.subarray(0, 32);
  try {
    return svmSignerKit.fromBytes(secret);
  } finally {
    wipeBytes(decoded);
  }
}

export const SvmSigner: SignerKit<SvmSigner> & {
  fromKeypairBase58: (b58: string) => SvmSigner;
} = {
  ...svmSignerKit,
  fromKeypairBase58: svmSignerFromKeypairBase58,
};
