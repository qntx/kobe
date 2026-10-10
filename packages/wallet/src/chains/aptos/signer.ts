import { bytesToHex } from "../../crypto/hex.ts";
import { SignError } from "../../errors/sign.ts";
import type { DerivedAccount } from "../../hd/account.ts";
import {
  ed25519SignerFromSecret,
  type Ed25519Signer,
  signerFromSecret,
  type SecretKey32,
  type SignOutput,
} from "../../sign/index.ts";
import { aptosAddressFromPublicKey, aptosTxSigningMessage } from "./hash.ts";

export interface AptosSigner {
  address(): string;
  publicKeyBytes(): Uint8Array;
  publicKeyHex(): string;
  /** Raw Ed25519 over the 32-byte digest — not on-chain verifiable. */
  signDigest(digest: Uint8Array): SignOutput;
  /** Raw Ed25519 over arbitrary bytes. No SignMessage trait. */
  signRaw(message: Uint8Array): SignOutput;
  /** Ed25519 over SHA3-256("APTOS::RawTransaction") || bcs_raw_tx. */
  signTransaction(bcsRawTx: Uint8Array): SignOutput;
  verify(message: Uint8Array, signature: Uint8Array): boolean;
  dispose(): void;
  [Symbol.dispose](): void;
}

function withPubkey(inner: Ed25519Signer, message: Uint8Array): SignOutput {
  const signed = inner.sign(message);
  return {
    scheme: "ed25519_with_pubkey",
    signature: signed.signature,
    publicKey: inner.publicKey(),
  };
}

class AptosSignerImpl implements AptosSigner {
  readonly #inner: Ed25519Signer;

  constructor(inner: Ed25519Signer) {
    this.#inner = inner;
  }

  address(): string {
    return aptosAddressFromPublicKey(this.#inner.publicKey());
  }

  publicKeyBytes(): Uint8Array {
    return this.#inner.publicKey();
  }

  publicKeyHex(): string {
    return bytesToHex(this.publicKeyBytes());
  }

  signDigest(digest: Uint8Array): SignOutput {
    const signed = this.#inner.signDigest(digest);
    if (signed.scheme !== "ed25519") {
      throw new SignError("signing_failed", "expected ed25519 output");
    }
    return {
      scheme: "ed25519_with_pubkey",
      signature: signed.signature,
      publicKey: this.#inner.publicKey(),
    };
  }

  signRaw(message: Uint8Array): SignOutput {
    return this.#inner.sign(message);
  }

  signTransaction(bcsRawTx: Uint8Array): SignOutput {
    return withPubkey(this.#inner, aptosTxSigningMessage(bcsRawTx));
  }

  verify(message: Uint8Array, signature: Uint8Array): boolean {
    const sig = signature.length === 64 ? signature : signature.subarray(0, 64);
    return this.#inner.verify(message, sig);
  }

  dispose(): void {
    this.#inner.dispose();
  }

  [Symbol.dispose](): void {
    this.dispose();
  }
}

export function aptosSignerFromSecretKey(key: SecretKey32): AptosSigner {
  return new AptosSignerImpl(ed25519SignerFromSecret(key));
}

export const {
  fromBytes: aptosSignerFromBytes,
  fromHex: aptosSignerFromHex,
  fromDerived: aptosSignerFromDerived,
} = signerFromSecret(aptosSignerFromSecretKey);

export function createAptosSigner(account: DerivedAccount): AptosSigner {
  return aptosSignerFromDerived(account);
}

export const AptosSigner = {
  fromSecretKey: aptosSignerFromSecretKey,
  fromBytes: aptosSignerFromBytes,
  fromHex: aptosSignerFromHex,
  fromDerived: aptosSignerFromDerived,
};
