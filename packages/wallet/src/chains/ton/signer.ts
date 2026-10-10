import { bytesToHex } from "../../crypto/hex.ts";
import type { DerivedAccount } from "../../hd/account.ts";
import {
  ed25519SignerFromSecret,
  type Ed25519Signer,
  signerFromSecret,
  type SecretKey32,
  type SignOutput,
} from "../../sign/index.ts";

/**
 * TON signer. Addresses depend on contract code + workchain, so this
 * exposes `identity()` (hex public key) instead of `address()`.
 *
 * No `SignMessage`: TON Connect / TonProof / cell-hash preimages are
 * caller-owned. `signTransaction` and `signRaw` are raw Ed25519.
 */
export interface TonSigner {
  identity(): string;
  publicKeyBytes(): Uint8Array;
  publicKeyHex(): string;
  /** Raw Ed25519 over the 32-byte digest. */
  signDigest(digest: Uint8Array): SignOutput;
  /** Raw Ed25519 over arbitrary bytes. */
  signRaw(message: Uint8Array): SignOutput;
  /** Raw Ed25519 over caller-built preimage (cell hash, ton_proof, …). */
  signTransaction(preimage: Uint8Array): SignOutput;
  verify(message: Uint8Array, signature: Uint8Array): boolean;
  dispose(): void;
  [Symbol.dispose](): void;
}

class TonSignerImpl implements TonSigner {
  readonly #inner: Ed25519Signer;

  constructor(inner: Ed25519Signer) {
    this.#inner = inner;
  }

  identity(): string {
    return this.publicKeyHex();
  }

  publicKeyBytes(): Uint8Array {
    return this.#inner.publicKey();
  }

  publicKeyHex(): string {
    return bytesToHex(this.publicKeyBytes());
  }

  signDigest(digest: Uint8Array): SignOutput {
    return this.#inner.signDigest(digest);
  }

  signRaw(message: Uint8Array): SignOutput {
    return this.#inner.sign(message);
  }

  signTransaction(preimage: Uint8Array): SignOutput {
    return this.#inner.sign(preimage);
  }

  verify(message: Uint8Array, signature: Uint8Array): boolean {
    return this.#inner.verify(message, signature);
  }

  dispose(): void {
    this.#inner.dispose();
  }

  [Symbol.dispose](): void {
    this.dispose();
  }
}

export function tonSignerFromSecretKey(key: SecretKey32): TonSigner {
  return new TonSignerImpl(ed25519SignerFromSecret(key));
}

export const {
  fromBytes: tonSignerFromBytes,
  fromHex: tonSignerFromHex,
  fromDerived: tonSignerFromDerived,
} = signerFromSecret(tonSignerFromSecretKey);

export function createTonSigner(account: DerivedAccount): TonSigner {
  return tonSignerFromDerived(account);
}

export const TonSigner = {
  fromSecretKey: tonSignerFromSecretKey,
  fromBytes: tonSignerFromBytes,
  fromHex: tonSignerFromHex,
  fromDerived: tonSignerFromDerived,
};
