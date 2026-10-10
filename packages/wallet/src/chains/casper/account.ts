import {
  createDerivedAccount,
  type DerivedAccount,
  type DerivedPublicKey,
} from "../../hd/account.ts";
import type { CasperKeyAlgo } from "./style.ts";

export interface CasperAccount extends DerivedAccount {
  readonly algo: CasperKeyAlgo;
  taggedPublicKeyHex(): string;
  accountHash(): string;
}

class CasperAccountImpl implements CasperAccount {
  readonly path: string;
  readonly publicKey: DerivedPublicKey;
  readonly address: string;
  readonly algo: CasperKeyAlgo;
  readonly #inner: DerivedAccount;
  readonly #tagged: string;

  constructor(inner: DerivedAccount, algo: CasperKeyAlgo, tagged: string) {
    this.#inner = inner;
    this.path = inner.path;
    this.publicKey = inner.publicKey;
    this.address = inner.address;
    this.algo = algo;
    this.#tagged = tagged;
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

  taggedPublicKeyHex(): string {
    return this.#tagged;
  }

  accountHash(): string {
    return this.address;
  }

  dispose(): void {
    this.#inner.dispose();
  }

  [Symbol.dispose](): void {
    this.dispose();
  }

  toString(): string {
    return `CasperAccount { path: ${this.path}, algo: ${this.algo}, address: ${this.address}, privateKey: [REDACTED] }`;
  }

  toJSON(): {
    path: string;
    algo: CasperKeyAlgo;
    address: string;
    taggedPublicKeyHex: string;
    privateKey: string;
  } {
    return {
      path: this.path,
      algo: this.algo,
      address: this.address,
      taggedPublicKeyHex: this.#tagged,
      privateKey: "[REDACTED]",
    };
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return this.toString();
  }
}

export function createCasperAccount(input: {
  path: string;
  privateKey: Uint8Array;
  publicKey: DerivedPublicKey;
  address: string;
  algo: CasperKeyAlgo;
  taggedPublicKeyHex: string;
}): CasperAccount {
  const inner = createDerivedAccount({
    path: input.path,
    privateKey: input.privateKey,
    publicKey: input.publicKey,
    address: input.address,
  });
  return new CasperAccountImpl(inner, input.algo, input.taggedPublicKeyHex);
}
