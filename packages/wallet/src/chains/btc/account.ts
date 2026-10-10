import { DeriveError } from "../../errors/derive.ts";
import {
  createDerivedAccount,
  type DerivedAccount,
  type DerivedPublicKey,
} from "../../hd/account.ts";
import type { BtcAddressType } from "./types.ts";

export interface BtcAccount extends DerivedAccount {
  privateKeyWif(): string;
  addressType(): BtcAddressType;
}

class BtcAccountImpl implements BtcAccount {
  readonly path: string;
  readonly publicKey: DerivedPublicKey;
  readonly address: string;
  readonly #inner: DerivedAccount;
  readonly #type: BtcAddressType;
  #wif: string | undefined;

  constructor(inner: DerivedAccount, wif: string, addressType: BtcAddressType) {
    this.#inner = inner;
    this.path = inner.path;
    this.publicKey = inner.publicKey;
    this.address = inner.address;
    this.#wif = wif;
    this.#type = addressType;
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

  privateKeyWif(): string {
    if (this.#wif === undefined) throw new DeriveError("input", "disposed");
    return this.#wif;
  }

  addressType(): BtcAddressType {
    return this.#type;
  }

  dispose(): void {
    this.#inner.dispose();
    this.#wif = undefined;
  }

  [Symbol.dispose](): void {
    this.dispose();
  }

  toString(): string {
    return `BtcAccount { path: ${this.path}, address: ${this.address}, wif: [REDACTED] }`;
  }

  toJSON(): { path: string; address: string; wif: string } {
    return { path: this.path, address: this.address, wif: "[REDACTED]" };
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return this.toString();
  }
}

export function createBtcAccount(input: {
  path: string;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  address: string;
  wif: string;
  addressType: BtcAddressType;
}): BtcAccount {
  const inner = createDerivedAccount({
    path: input.path,
    privateKey: input.privateKey,
    publicKey: { kind: "secp256k1-compressed", bytes: input.publicKey },
    address: input.address,
  });
  return new BtcAccountImpl(inner, input.wif, input.addressType);
}
