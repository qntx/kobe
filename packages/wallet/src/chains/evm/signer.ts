import { bytesToHex } from "../../crypto/hex.ts";
import { keccak256 } from "../../crypto/index.ts";
import { SignError } from "../../errors/sign.ts";
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
import { evmAddressFromUncompressed } from "./address.ts";
import { hashTypedDataJson } from "./eip712.ts";
import { encodeSignedTypedTx } from "./rlp.ts";

export interface EvmSigner {
  address(): string;
  publicKeyBytes(): Uint8Array;
  publicKeyHex(): string;
  signDigest(digest: Uint8Array): SignOutput;
  signMessage(message: Uint8Array): SignOutput;
  signTypedData(typedDataJson: string): SignOutput;
  signTransaction(unsignedTx: Uint8Array): SignOutput;
  encodeSignedTransaction(unsignedTx: Uint8Array, signature: SignOutput): Uint8Array;
  verifyHash(hash: Uint8Array, signature: Uint8Array): boolean;
  dispose(): void;
  [Symbol.dispose](): void;
}

class EvmSignerImpl implements EvmSigner {
  readonly #inner: Secp256k1Signer;

  constructor(inner: Secp256k1Signer) {
    this.#inner = inner;
  }

  address(): string {
    return evmAddressFromUncompressed(this.#inner.uncompressedPublicKey());
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
    const prefix = `\x19Ethereum Signed Message:\n${message.length}`;
    const prefixBytes = new TextEncoder().encode(prefix);
    const data = new Uint8Array(prefixBytes.length + message.length);
    data.set(prefixBytes, 0);
    data.set(message, prefixBytes.length);
    const digest = keccak256(data);
    return withVOffset(this.#inner.signPrehashRecoverable(digest), EIP191_OFFSET);
  }

  signTypedData(typedDataJson: string): SignOutput {
    const digest = hashTypedDataJson(typedDataJson);
    return withVOffset(this.#inner.signPrehashRecoverable(digest), EIP191_OFFSET);
  }

  signTransaction(unsignedTx: Uint8Array): SignOutput {
    return this.#inner.signPrehashRecoverable(keccak256(unsignedTx));
  }

  encodeSignedTransaction(unsignedTx: Uint8Array, signature: SignOutput): Uint8Array {
    if (signature.scheme !== "ecdsa_recoverable") {
      throw new SignError("invalid_signature", "expected Ecdsa signature output");
    }
    return encodeSignedTypedTx(
      unsignedTx,
      signature.v,
      signature.signature.subarray(0, 32),
      signature.signature.subarray(32, 64),
    );
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

export function evmSignerFromSecretKey(key: SecretKey32): EvmSigner {
  return new EvmSignerImpl(secp256k1SignerFromSecret(key));
}

export const {
  fromBytes: evmSignerFromBytes,
  fromHex: evmSignerFromHex,
  fromDerived: evmSignerFromDerived,
} = signerFromSecret(evmSignerFromSecretKey);

export function createEvmSigner(account: DerivedAccount): EvmSigner {
  return evmSignerFromDerived(account);
}

export const EvmSigner = {
  fromSecretKey: evmSignerFromSecretKey,
  fromBytes: evmSignerFromBytes,
  fromHex: evmSignerFromHex,
  fromDerived: evmSignerFromDerived,
};
