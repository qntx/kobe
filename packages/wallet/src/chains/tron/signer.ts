import { bytesToHex } from "../../crypto/hex.ts";
import { keccak256, sha256Bytes } from "../../crypto/index.ts";
import type { DerivedAccount } from "../../hd/account.ts";
import {
  EIP191_OFFSET,
  secp256k1SignerFromSecret,
  signerFromSecret,
  type SecretKey32,
  type Secp256k1Signer,
  type SignOutput,
  withVOffset,
} from "../../sign/index.ts";
import { tronAddressFromUncompressed } from "./address.ts";

export interface TronSigner {
  address(): string;
  publicKeyBytes(): Uint8Array;
  publicKeyHex(): string;
  signDigest(digest: Uint8Array): SignOutput;
  signMessage(message: Uint8Array): SignOutput;
  signTransaction(rawData: Uint8Array): SignOutput;
  verifyHash(hash: Uint8Array, signature: Uint8Array): boolean;
  dispose(): void;
  [Symbol.dispose](): void;
}

class TronSignerImpl implements TronSigner {
  readonly #inner: Secp256k1Signer;

  constructor(inner: Secp256k1Signer) {
    this.#inner = inner;
  }

  address(): string {
    return tronAddressFromUncompressed(this.#inner.uncompressedPublicKey());
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

  signMessage(message: Uint8Array): SignOutput {
    const prefix = `\x19TRON Signed Message:\n${message.length}`;
    const prefixBytes = new TextEncoder().encode(prefix);
    const data = new Uint8Array(prefixBytes.length + message.length);
    data.set(prefixBytes, 0);
    data.set(message, prefixBytes.length);
    return withVOffset(this.#inner.signPrehashRecoverable(keccak256(data)), EIP191_OFFSET);
  }

  signTransaction(rawData: Uint8Array): SignOutput {
    return this.#inner.signPrehashRecoverable(sha256Bytes(rawData));
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

export function tronSignerFromSecretKey(key: SecretKey32): TronSigner {
  return new TronSignerImpl(secp256k1SignerFromSecret(key));
}

export const {
  fromBytes: tronSignerFromBytes,
  fromHex: tronSignerFromHex,
  fromDerived: tronSignerFromDerived,
} = signerFromSecret(tronSignerFromSecretKey);

export function createTronSigner(account: DerivedAccount): TronSigner {
  return tronSignerFromDerived(account);
}

export const TronSigner = {
  fromSecretKey: tronSignerFromSecretKey,
  fromBytes: tronSignerFromBytes,
  fromHex: tronSignerFromHex,
  fromDerived: tronSignerFromDerived,
};
