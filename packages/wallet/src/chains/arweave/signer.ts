import { bytesToHex } from "../../crypto/hex.ts";
import { sha256Bytes } from "../../crypto/index.ts";
import { SignError } from "../../errors/sign.ts";
import type { DerivedAccount } from "../../hd/account.ts";
import {
  secp256k1SignerFromSecret,
  signerFromSecret,
  type SecretKey32,
  type Secp256k1Signer,
  type SignOutput,
  signOutputToBytes,
} from "../../sign/index.ts";
import {
  arweaveAddressFromCompressed,
  arweaveOwnerFromCompressed,
  arweaveTransactionId,
  SIGNATURE_LEN,
} from "./address.ts";
import {
  assertFormat2,
  type Format2EcdsaFields,
  signatureDataSegmentV2Ecdsa,
} from "./deep-hash.ts";

/**
 * Arweave ECDSA signer (protocol 2.9+).
 * No `SignMessage`. Format=1 / RSA are out of scope.
 */
export interface ArweaveSigner {
  address(): string;
  owner(): string;
  publicKeyBytes(): Uint8Array;
  publicKeyHex(): string;
  signDigest(digest: Uint8Array): SignOutput;
  /** SHA-256(msg) then recoverable ECDSA. Typical msg is the 48-byte deep-hash. */
  signPayload(msg: Uint8Array): SignOutput;
  signFormat2(fields: Format2EcdsaFields): SignOutput;
  verifyDigest(digest: Uint8Array, signature65: Uint8Array): boolean;
  verifyPayload(msg: Uint8Array, signature65: Uint8Array): boolean;
  dispose(): void;
  [Symbol.dispose](): void;
}

function compactSig(signature65: Uint8Array): Uint8Array {
  if (signature65.length !== SIGNATURE_LEN) {
    throw new SignError(
      "invalid_signature",
      `arweave signature must be ${SIGNATURE_LEN} bytes, got ${signature65.length}`,
    );
  }
  return signature65.subarray(0, 64);
}

class ArweaveSignerImpl implements ArweaveSigner {
  readonly #inner: Secp256k1Signer;

  constructor(inner: Secp256k1Signer) {
    this.#inner = inner;
  }

  address(): string {
    return arweaveAddressFromCompressed(this.#inner.compressedPublicKey());
  }

  owner(): string {
    return arweaveOwnerFromCompressed(this.#inner.compressedPublicKey());
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

  signPayload(msg: Uint8Array): SignOutput {
    return this.#inner.signPrehashRecoverable(sha256Bytes(msg));
  }

  signFormat2(fields: Format2EcdsaFields): SignOutput {
    assertFormat2(fields);
    return this.signPayload(signatureDataSegmentV2Ecdsa(fields));
  }

  verifyDigest(digest: Uint8Array, signature65: Uint8Array): boolean {
    return this.#inner.verifyPrehash(digest, compactSig(signature65));
  }

  verifyPayload(msg: Uint8Array, signature65: Uint8Array): boolean {
    return this.verifyDigest(sha256Bytes(msg), signature65);
  }

  dispose(): void {
    this.#inner.dispose();
  }

  [Symbol.dispose](): void {
    this.dispose();
  }
}

export function arweaveSignerFromSecretKey(key: SecretKey32): ArweaveSigner {
  return new ArweaveSignerImpl(secp256k1SignerFromSecret(key));
}

export const {
  fromBytes: arweaveSignerFromBytes,
  fromHex: arweaveSignerFromHex,
  fromDerived: arweaveSignerFromDerived,
} = signerFromSecret(arweaveSignerFromSecretKey);

export function createArweaveSigner(account: DerivedAccount): ArweaveSigner {
  return arweaveSignerFromDerived(account);
}

export function arweaveSignature65(out: SignOutput): Uint8Array {
  if (out.scheme !== "ecdsa_recoverable") {
    throw new SignError("invalid_signature", "expected recoverable ECDSA SignOutput");
  }
  return signOutputToBytes(out);
}

export function arweaveTxIdFromOutput(out: SignOutput): string {
  return arweaveTransactionId(arweaveSignature65(out));
}

export const ArweaveSigner = {
  fromSecretKey: arweaveSignerFromSecretKey,
  fromBytes: arweaveSignerFromBytes,
  fromHex: arweaveSignerFromHex,
  fromDerived: arweaveSignerFromDerived,
};
