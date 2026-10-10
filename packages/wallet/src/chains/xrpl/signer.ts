import { bytesToHex } from "../../crypto/hex.ts";
import { SignError } from "../../errors/sign.ts";
import type { DerivedAccount } from "../../hd/account.ts";
import {
  secp256k1SignerFromSecret,
  signerFromSecret,
  type SecretKey32,
  type Secp256k1Signer,
  type SignOutput,
} from "../../sign/index.ts";
import { xrplAddressFromCompressed, xrplTxDigest } from "./address.ts";

/**
 * XRPL signer. `signTransaction` is DER-ECDSA over SHA-512-half(`STX\0 || tx`).
 * No `SignMessage`.
 */
export interface XrplSigner {
  address(): string;
  publicKeyBytes(): Uint8Array;
  publicKeyHex(): string;
  /** DER-ECDSA over the 32-byte digest. */
  signDigest(digest: Uint8Array): SignOutput;
  /** DER-ECDSA over SHA-512-half(`STX\0 || tx_bytes`). */
  signTransaction(txBytes: Uint8Array): SignOutput;
  verifyHashDer(hash: Uint8Array, signatureDer: Uint8Array): boolean;
  dispose(): void;
  [Symbol.dispose](): void;
}

class XrplSignerImpl implements XrplSigner {
  readonly #inner: Secp256k1Signer;

  constructor(inner: Secp256k1Signer) {
    this.#inner = inner;
  }

  address(): string {
    return xrplAddressFromCompressed(this.#inner.compressedPublicKey());
  }

  publicKeyBytes(): Uint8Array {
    return this.#inner.compressedPublicKey();
  }

  publicKeyHex(): string {
    return bytesToHex(this.publicKeyBytes());
  }

  signDigest(digest: Uint8Array): SignOutput {
    return this.#inner.signPrehashDer(digest);
  }

  signTransaction(txBytes: Uint8Array): SignOutput {
    if (txBytes.length === 0) {
      throw new SignError("invalid_transaction", "transaction bytes must not be empty");
    }
    return this.#inner.signPrehashDer(xrplTxDigest(txBytes));
  }

  verifyHashDer(hash: Uint8Array, signatureDer: Uint8Array): boolean {
    return this.#inner.verifyPrehashDer(hash, signatureDer);
  }

  dispose(): void {
    this.#inner.dispose();
  }

  [Symbol.dispose](): void {
    this.dispose();
  }
}

export function xrplSignerFromSecretKey(key: SecretKey32): XrplSigner {
  return new XrplSignerImpl(secp256k1SignerFromSecret(key));
}

export const {
  fromBytes: xrplSignerFromBytes,
  fromHex: xrplSignerFromHex,
  fromDerived: xrplSignerFromDerived,
} = signerFromSecret(xrplSignerFromSecretKey);

export function createXrplSigner(account: DerivedAccount): XrplSigner {
  return xrplSignerFromDerived(account);
}

export const XrplSigner = {
  fromSecretKey: xrplSignerFromSecretKey,
  fromBytes: xrplSignerFromBytes,
  fromHex: xrplSignerFromHex,
  fromDerived: xrplSignerFromDerived,
};
