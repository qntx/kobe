import { createDerivedAccount } from "../../hd/account.ts";
import type { DerivedAccount, DerivedPublicKey } from "../../hd/account.ts";
import { wipeBytes } from "../../secret/dispose.ts";
import { encodeNsec } from "./nip19.ts";

export type NostrAccount = {
  nsec(): string;
  npub(): string;
} & DerivedAccount;

class NostrAccountImpl implements NostrAccount {
  readonly path: string;
  readonly publicKey: DerivedPublicKey;
  readonly address: string;
  readonly #inner: DerivedAccount;

  constructor(inner: DerivedAccount) {
    this.#inner = inner;
    this.path = inner.path;
    this.publicKey = inner.publicKey;
    this.address = inner.address;
  }

  privateKeyBytes(): Uint8Array {
    return this.#inner.privateKeyBytes();
  }

  privateKeyHex(): string {
    return this.#inner.privateKeyHex();
  }

  publicKeyBytes(): Uint8Array {
    return this.#inner.publicKeyBytes();
  }

  publicKeyHex(): string {
    return this.#inner.publicKeyHex();
  }

  /** Bech32 `nsec` computed on demand from the private key; the account stores no copy. */
  nsec(): string {
    const sk = this.#inner.privateKeyBytes();
    try {
      return encodeNsec(sk);
    } finally {
      wipeBytes(sk);
    }
  }

  npub(): string {
    return this.address;
  }

  dispose(): void {
    this.#inner.dispose();
  }

  [Symbol.dispose](): void {
    this.dispose();
  }

  toString(): string {
    return `NostrAccount { path: ${this.path}, npub: ${this.address}, nsec: [REDACTED] }`;
  }

  toJSON(): { path: string; npub: string; nsec: string } {
    return { path: this.path, npub: this.address, nsec: "[REDACTED]" };
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return this.toString();
  }
}

export function createNostrAccount(input: {
  path: string;
  privateKey: Uint8Array;
  xonlyPublicKey: Uint8Array;
  npub: string;
}): NostrAccount {
  const inner = createDerivedAccount({
    path: input.path,
    privateKey: input.privateKey,
    publicKey: { kind: "secp256k1-xonly", bytes: input.xonlyPublicKey },
    address: input.npub,
  });
  return new NostrAccountImpl(inner);
}
