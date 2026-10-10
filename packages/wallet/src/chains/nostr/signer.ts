import { bytesToHex } from "../../crypto/hex.ts";
import { sha256Bytes } from "../../crypto/index.ts";
import { SignError } from "../../errors/sign.ts";
import type { DerivedAccount } from "../../hd/account.ts";
import { wipeBytes } from "../../secret/dispose.ts";
import {
  schnorrSignerFromSecret,
  signerFromSecret,
  type SecretKey32,
  type SchnorrSigner,
  type SignOutput,
} from "../../sign/index.ts";
import { decodeNip19, encodeNpub, encodeNsec, NSEC_HRP } from "./nip19.ts";

export interface NostrSigner {
  address(): string;
  npub(): string;
  nsec(): string;
  publicKeyBytes(): Uint8Array;
  publicKeyHex(): string;
  signDigest(digest: Uint8Array): SignOutput;
  signMessage(message: Uint8Array): SignOutput;
  /** SHA-256(serialized NIP-01 event) then BIP-340. */
  signTransaction(serializedEvent: Uint8Array): SignOutput;
  verify(message: Uint8Array, signature: Uint8Array): boolean;
  dispose(): void;
  [Symbol.dispose](): void;
}

class NostrSignerImpl implements NostrSigner {
  readonly #inner: SchnorrSigner;
  readonly #sk: Uint8Array;
  #disposed = false;

  constructor(inner: SchnorrSigner, sk: Uint8Array) {
    this.#inner = inner;
    this.#sk = sk;
  }

  #assertLive(): void {
    if (this.#disposed) throw new SignError("invalid_key", "disposed");
  }

  address(): string {
    this.#assertLive();
    return encodeNpub(this.#inner.xonlyPublicKey());
  }

  npub(): string {
    return this.address();
  }

  nsec(): string {
    this.#assertLive();
    return encodeNsec(this.#sk);
  }

  publicKeyBytes(): Uint8Array {
    this.#assertLive();
    return this.#inner.xonlyPublicKey();
  }

  publicKeyHex(): string {
    return bytesToHex(this.publicKeyBytes());
  }

  signDigest(digest: Uint8Array): SignOutput {
    this.#assertLive();
    return this.#inner.signDigest(digest);
  }

  signMessage(message: Uint8Array): SignOutput {
    this.#assertLive();
    return this.#inner.sign(message);
  }

  signTransaction(serializedEvent: Uint8Array): SignOutput {
    return this.signDigest(sha256Bytes(serializedEvent));
  }

  verify(message: Uint8Array, signature: Uint8Array): boolean {
    this.#assertLive();
    return this.#inner.verify(message, signature);
  }

  dispose(): void {
    if (this.#disposed) return;
    wipeBytes(this.#sk);
    this.#inner.dispose();
    this.#disposed = true;
  }

  [Symbol.dispose](): void {
    this.dispose();
  }
}

export function nostrSignerFromSecretKey(key: SecretKey32): NostrSigner {
  const sk = key.toBytes();
  return new NostrSignerImpl(schnorrSignerFromSecret(key), sk);
}

export const {
  fromBytes: nostrSignerFromBytes,
  fromHex: nostrSignerFromHex,
  fromDerived: nostrSignerFromDerived,
} = signerFromSecret(nostrSignerFromSecretKey);

export function nostrSignerFromNsec(nsec: string): NostrSigner {
  return nostrSignerFromBytes(decodeNip19(nsec, NSEC_HRP));
}

export function createNostrSigner(account: DerivedAccount): NostrSigner {
  return nostrSignerFromDerived(account);
}

export const NostrSigner = {
  fromSecretKey: nostrSignerFromSecretKey,
  fromBytes: nostrSignerFromBytes,
  fromHex: nostrSignerFromHex,
  fromDerived: nostrSignerFromDerived,
  fromNsec: nostrSignerFromNsec,
};
