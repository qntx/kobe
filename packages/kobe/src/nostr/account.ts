import { createDerivedAccount } from "../core/account.ts";
import type { DerivedAccount } from "../core/account.ts";
import { KobeError } from "../core/error.ts";

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
  #nsec: string | undefined;

  constructor(inner: DerivedAccount, nsec: string) {
    this.#inner = inner;
    this.path = inner.path;
    this.publicKey = inner.publicKey;
    this.address = inner.address;
    this.#nsec = nsec;
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
    if (this.#nsec === undefined) {
      throw new KobeError("input", "disposed");
    }
    return this.#nsec;
  }

  npub(): string {
    return this.address;
  }

  dispose(): void {
    this.#inner.dispose();
    this.#nsec = undefined;
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
  nsec: string;
}): NostrAccount {
  const inner = createDerivedAccount({
    path: input.path,
    privateKey: input.privateKey,
    publicKey: { kind: "secp256k1-xonly", bytes: input.xonlyPublicKey },
    address: input.npub,
  });
  return new NostrAccountImpl(inner, input.nsec);
}
