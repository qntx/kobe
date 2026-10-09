import { createDerivedAccount } from "../core/account.ts";
import type { DerivedAccount } from "../core/account.ts";
import { wipeBytes } from "../core/bytes.ts";
import { encodeNsec } from "./nip19.ts";

/** A Nostr-specific derived account — `DerivedAccount` plus NIP-19 `nsec`. */
export type NostrAccount = {
  /** NIP-19 `nsec1…` bech32 encoding of the private key. @throws KobeError input if disposed */
  nsec: () => string;
  /** NIP-19 `npub1…` bech32 encoding of the x-only public key (alias of `address`). */
  npub: () => string;
} & DerivedAccount;

class NostrAccountImpl implements NostrAccount {
  readonly path: string;
  readonly publicKey: DerivedAccount["publicKey"];
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

  toString(): string {
    return `NostrAccount { path: ${this.path}, npub: ${this.address}, nsec: [REDACTED] }`;
  }

  toJSON(): { path: string; npub: string; nsec: string } {
    return { path: this.path, npub: this.address, nsec: "[REDACTED]" };
  }
}

/** Internal: assemble a `NostrAccount` from raw derivation output. */
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
