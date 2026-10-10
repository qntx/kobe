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
import {
  bcsSerializeBytes,
  SUI_ED25519_FLAG,
  SUI_MSG_INTENT,
  SUI_TX_INTENT,
  suiAddressFromPublicKey,
  suiIntentHash,
} from "./hash.ts";

export interface SuiSigner {
  address(): string;
  publicKeyBytes(): Uint8Array;
  publicKeyHex(): string;
  /** Raw Ed25519 over the 32-byte digest — not on-chain verifiable. */
  signDigest(digest: Uint8Array): SignOutput;
  /** PersonalMessage intent [3,0,0] || BCS(message). */
  signMessage(message: Uint8Array): SignOutput;
  /** TransactionData intent [0,0,0] || tx_bytes. */
  signTransaction(txBytes: Uint8Array): SignOutput;
  /** `flag(0x00) || sig(64) || pk(32)` */
  encodeSignature(signature: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array): boolean;
  dispose(): void;
  [Symbol.dispose](): void;
}

function withPubkey(inner: Ed25519Signer, digest: Uint8Array): SignOutput {
  const signed = inner.sign(digest);
  return {
    scheme: "ed25519_with_pubkey",
    signature: signed.signature,
    publicKey: inner.publicKey(),
  };
}

class SuiSignerImpl implements SuiSigner {
  readonly #inner: Ed25519Signer;

  constructor(inner: Ed25519Signer) {
    this.#inner = inner;
  }

  address(): string {
    return suiAddressFromPublicKey(this.#inner.publicKey());
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

  signMessage(message: Uint8Array): SignOutput {
    const digest = suiIntentHash(SUI_MSG_INTENT, bcsSerializeBytes(message));
    return withPubkey(this.#inner, digest);
  }

  signTransaction(txBytes: Uint8Array): SignOutput {
    const digest = suiIntentHash(SUI_TX_INTENT, txBytes);
    return withPubkey(this.#inner, digest);
  }

  encodeSignature(signature: Uint8Array): Uint8Array {
    if (signature.length !== 64) {
      throw new SignError("invalid_signature", "ed25519 signature must be 64 bytes");
    }
    const pk = this.#inner.publicKey();
    const out = new Uint8Array(97);
    out[0] = SUI_ED25519_FLAG;
    out.set(signature, 1);
    out.set(pk, 65);
    return out;
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

export function suiSignerFromSecretKey(key: SecretKey32): SuiSigner {
  return new SuiSignerImpl(ed25519SignerFromSecret(key));
}

export const {
  fromBytes: suiSignerFromBytes,
  fromHex: suiSignerFromHex,
  fromDerived: suiSignerFromDerived,
} = signerFromSecret(suiSignerFromSecretKey);

export function createSuiSigner(account: DerivedAccount): SuiSigner {
  return suiSignerFromDerived(account);
}

export const SuiSigner = {
  fromSecretKey: suiSignerFromSecretKey,
  fromBytes: suiSignerFromBytes,
  fromHex: suiSignerFromHex,
  fromDerived: suiSignerFromDerived,
};
