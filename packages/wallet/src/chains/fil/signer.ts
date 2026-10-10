import { bytesToHex } from "../../crypto/hex.ts";
import type { DerivedAccount } from "../../hd/account.ts";
import {
  secp256k1SignerFromSecret,
  signerFromSecret,
  type SecretKey32,
  type Secp256k1Signer,
  type SignOutput,
} from "../../sign/index.ts";
import { filAddressFromUncompressed, filBlake2b256 } from "./address.ts";

/**
 * Filecoin f1 signer. `signTransaction` is ECDSA over BLAKE2b-256(bytes).
 * Callers that follow the spec pass CID bytes of the CBOR `Message`.
 * No `SignMessage`.
 */
export interface FilSigner {
  address(): string;
  publicKeyBytes(): Uint8Array;
  publicKeyHex(): string;
  signDigest(digest: Uint8Array): SignOutput;
  /** ECDSA(BLAKE2b-256(tx_bytes)), raw v 0|1. */
  signTransaction(txBytes: Uint8Array): SignOutput;
  verifyHash(hash: Uint8Array, signature: Uint8Array): boolean;
  dispose(): void;
  [Symbol.dispose](): void;
}

class FilSignerImpl implements FilSigner {
  readonly #inner: Secp256k1Signer;

  constructor(inner: Secp256k1Signer) {
    this.#inner = inner;
  }

  address(): string {
    return filAddressFromUncompressed(this.#inner.uncompressedPublicKey());
  }

  publicKeyBytes(): Uint8Array {
    return this.#inner.compressedPublicKey();
  }

  publicKeyHex(): string {
    return bytesToHex(this.publicKeyBytes());
  }

  signDigest(digest: Uint8Array): SignOutput {
    return this.#inner.signDigest(digest);
  }

  signTransaction(txBytes: Uint8Array): SignOutput {
    return this.#inner.signPrehashRecoverable(filBlake2b256(txBytes));
  }

  verifyHash(hash: Uint8Array, signature: Uint8Array): boolean {
    const compact = signature.length === 65 ? signature.subarray(0, 64) : signature;
    return this.#inner.verifyPrehash(hash, compact);
  }

  dispose(): void {
    this.#inner.dispose();
  }

  [Symbol.dispose](): void {
    this.dispose();
  }
}

export function filSignerFromSecretKey(key: SecretKey32): FilSigner {
  return new FilSignerImpl(secp256k1SignerFromSecret(key));
}

export const {
  fromBytes: filSignerFromBytes,
  fromHex: filSignerFromHex,
  fromDerived: filSignerFromDerived,
} = signerFromSecret(filSignerFromSecretKey);

export function createFilSigner(account: DerivedAccount): FilSigner {
  return filSignerFromDerived(account);
}

export const FilSigner = {
  fromSecretKey: filSignerFromSecretKey,
  fromBytes: filSignerFromBytes,
  fromHex: filSignerFromHex,
  fromDerived: filSignerFromDerived,
};
