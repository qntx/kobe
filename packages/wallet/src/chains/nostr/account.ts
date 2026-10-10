import { DeriveError } from "../../errors/derive.ts";
import {
  createDerivedAccount,
  type DerivedAccount,
  type DerivedPublicKey,
} from "../../hd/account.ts";

export interface NostrAccount extends DerivedAccount {
  nsec(): string;
  npub(): string;
}

class NostrAccountImpl implements NostrAccount {
  readonly path: string;
  readonly publicKey: DerivedPublicKey;
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
    if (this.#nsec === undefined) throw new DeriveError("input", "disposed");
    return this.#nsec;
  }

  npub(): string {
    return this.address;
  }

  dispose(): void {
    this.#inner.dispose();
    this.#nsec = undefined;
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
