import { bytesToHex } from "../../crypto/hex.ts";
import { sha256Bytes } from "../../crypto/index.ts";
import type { DerivedAccount } from "../../hd/account.ts";
import {
  secp256k1SignerFromSecret,
  signerFromSecret,
  type SecretKey32,
  type Secp256k1Signer,
  type SignOutput,
} from "../../sign/index.ts";
import { cosmosAddressWithHrp } from "./address.ts";

export interface CosmosSigner {
  address(): string;
  addressWithHrp(hrp: string): string;
  publicKeyBytes(): Uint8Array;
  publicKeyHex(): string;
  signDigest(digest: Uint8Array): SignOutput;
  /** SHA-256(SignDoc bytes) + ECDSA. No SignMessage (ADR-036 is caller-owned). */
  signTransaction(signDoc: Uint8Array): SignOutput;
  verifyHash(hash: Uint8Array, signature: Uint8Array): boolean;
  dispose(): void;
  [Symbol.dispose](): void;
}

class CosmosSignerImpl implements CosmosSigner {
  readonly #inner: Secp256k1Signer;

  constructor(inner: Secp256k1Signer) {
    this.#inner = inner;
  }

  address(): string {
    return this.addressWithHrp("cosmos");
  }

  addressWithHrp(hrp: string): string {
    return cosmosAddressWithHrp(this.#inner.compressedPublicKey(), hrp);
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

  signTransaction(signDoc: Uint8Array): SignOutput {
    return this.#inner.signPrehashRecoverable(sha256Bytes(signDoc));
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

export function cosmosSignerFromSecretKey(key: SecretKey32): CosmosSigner {
  return new CosmosSignerImpl(secp256k1SignerFromSecret(key));
}

export const {
  fromBytes: cosmosSignerFromBytes,
  fromHex: cosmosSignerFromHex,
  fromDerived: cosmosSignerFromDerived,
} = signerFromSecret(cosmosSignerFromSecretKey);

export function createCosmosSigner(account: DerivedAccount): CosmosSigner {
  return cosmosSignerFromDerived(account);
}

export const CosmosSigner = {
  fromSecretKey: cosmosSignerFromSecretKey,
  fromBytes: cosmosSignerFromBytes,
  fromHex: cosmosSignerFromHex,
  fromDerived: cosmosSignerFromDerived,
};
