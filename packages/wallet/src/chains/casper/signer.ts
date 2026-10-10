import { bytesToHex } from "../../crypto/hex.ts";
import { SignError } from "../../errors/sign.ts";
import type { DerivedAccount } from "../../hd/account.ts";
import {
  ed25519SignerFromSecret,
  type Ed25519Signer,
  secp256k1SignerFromSecret,
  signerFromSecret,
  type SecretKey32,
  type Secp256k1Signer,
  type SignOutput,
} from "../../sign/index.ts";
import { ED25519_TAG, SECP256K1_TAG, taggedPublicKeyHex } from "./address.ts";
import type { CasperKeyAlgo } from "./style.ts";

/**
 * Casper dual-curve signer. Deploy serialization is caller-owned.
 * Feed BLAKE2b-256 deploy hash to `signDigest` / `signDeployHash`.
 * No `SignMessage`, no `signTransaction`, no `address` (AccountHash is HD).
 */
export interface CasperSigner {
  algo(): CasperKeyAlgo;
  publicKeyBytes(): Uint8Array;
  publicKeyHex(): string;
  taggedPublicKeyHex(): string;
  signDigest(digest: Uint8Array): SignOutput;
  /** secp: 32-byte digest; ed25519: RFC 8032 over the bytes. */
  signBytes(message: Uint8Array): SignOutput;
  signDeployHash(digest: Uint8Array): SignOutput;
  dispose(): void;
  [Symbol.dispose](): void;
}

class CasperSignerImpl implements CasperSigner {
  readonly #algo: CasperKeyAlgo;
  readonly #secp: Secp256k1Signer | undefined;
  readonly #ed: Ed25519Signer | undefined;

  constructor(
    algo: CasperKeyAlgo,
    secp: Secp256k1Signer | undefined,
    ed: Ed25519Signer | undefined,
  ) {
    this.#algo = algo;
    this.#secp = secp;
    this.#ed = ed;
  }

  algo(): CasperKeyAlgo {
    return this.#algo;
  }

  #secpLive(): Secp256k1Signer {
    if (!this.#secp) throw new SignError("invalid_key", "missing secp256k1 key");
    return this.#secp;
  }

  #edLive(): Ed25519Signer {
    if (!this.#ed) throw new SignError("invalid_key", "missing ed25519 key");
    return this.#ed;
  }

  publicKeyBytes(): Uint8Array {
    if (this.#algo === "secp256k1") return this.#secpLive().compressedPublicKey();
    return this.#edLive().publicKey();
  }

  publicKeyHex(): string {
    return bytesToHex(this.publicKeyBytes());
  }

  taggedPublicKeyHex(): string {
    const tag = this.#algo === "secp256k1" ? SECP256K1_TAG : ED25519_TAG;
    return taggedPublicKeyHex(tag, this.publicKeyBytes());
  }

  signDigest(digest: Uint8Array): SignOutput {
    if (this.#algo === "secp256k1") return this.#secpLive().signDigest(digest);
    return this.#edLive().sign(digest);
  }

  signBytes(message: Uint8Array): SignOutput {
    if (this.#algo === "secp256k1") {
      if (message.length !== 32) {
        throw new SignError(
          "invalid_message",
          `casper secp signBytes expects 32-byte digest, got ${message.length}`,
        );
      }
      return this.#secpLive().signDigest(message);
    }
    return this.#edLive().sign(message);
  }

  signDeployHash(digest: Uint8Array): SignOutput {
    return this.signDigest(digest);
  }

  dispose(): void {
    this.#secp?.dispose();
    this.#ed?.dispose();
  }

  [Symbol.dispose](): void {
    this.dispose();
  }
}

function algoFromAccount(account: DerivedAccount): CasperKeyAlgo {
  switch (account.publicKey.kind) {
    case "secp256k1-compressed":
      return "secp256k1";
    case "ed25519":
      return "ed25519";
    default:
      throw new SignError(
        "invalid_key",
        `casper: cannot infer key algo from ${account.publicKey.kind}`,
      );
  }
}

export function casperSignerFromSecretKey(
  key: SecretKey32,
  algo: CasperKeyAlgo = "secp256k1",
): CasperSigner {
  if (algo === "secp256k1") {
    return new CasperSignerImpl(algo, secp256k1SignerFromSecret(key), undefined);
  }
  return new CasperSignerImpl(algo, undefined, ed25519SignerFromSecret(key));
}

const casperFactories = signerFromSecret(casperSignerFromSecretKey);

export const casperSignerFromBytes = casperFactories.fromBytes;
export const casperSignerFromHex = casperFactories.fromHex;

export function casperSignerFromDerived(account: DerivedAccount): CasperSigner {
  return casperFactories.fromDerived(account, algoFromAccount(account));
}

export function createCasperSigner(account: DerivedAccount): CasperSigner {
  return casperSignerFromDerived(account);
}

export const CasperSigner = {
  fromSecretKey: casperSignerFromSecretKey,
  fromBytes: casperSignerFromBytes,
  fromHex: casperSignerFromHex,
  fromDerived: casperSignerFromDerived,
};
