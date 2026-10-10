import { base58 } from "@scure/base";

import { DeriveError } from "../../errors/derive.ts";
import { createDerivedAccount } from "../../hd/account.ts";
import type { DerivedAccount, DerivedPublicKey, SvmAccount } from "../../hd/account.ts";
import { wipeBytes } from "../../secret/dispose.ts";

class SvmAccountImpl implements SvmAccount {
  readonly path: string;
  readonly publicKey: DerivedPublicKey;
  readonly address: string;
  readonly #inner: DerivedAccount;
  #keypair: string | undefined;

  constructor(inner: DerivedAccount, keypairBase58: string) {
    this.#inner = inner;
    this.path = inner.path;
    this.publicKey = inner.publicKey;
    this.address = inner.address;
    this.#keypair = keypairBase58;
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

  keypairBase58(): string {
    if (this.#keypair === undefined) {
      throw new DeriveError("input", "disposed");
    }
    return this.#keypair;
  }

  dispose(): void {
    this.#inner.dispose();
    this.#keypair = undefined;
  }

  [Symbol.dispose](): void {
    this.dispose();
  }

  toString(): string {
    return `SvmAccount { path: ${this.path}, address: ${this.address}, keypair: [REDACTED] }`;
  }

  toJSON(): { path: string; address: string; keypairBase58: string } {
    return { path: this.path, address: this.address, keypairBase58: "[REDACTED]" };
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return this.toString();
  }
}

export function createSvmAccount(input: {
  path: string;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}): SvmAccount {
  if (input.publicKey.length !== 32) {
    throw new DeriveError(
      "crypto",
      `ed25519 public key requires 32 bytes, got ${input.publicKey.length}`,
    );
  }
  const pair = new Uint8Array(64);
  pair.set(input.privateKey, 0);
  pair.set(input.publicKey, 32);
  const keypair = base58.encode(pair);
  wipeBytes(pair);
  const inner = createDerivedAccount({
    path: input.path,
    privateKey: input.privateKey,
    publicKey: { kind: "ed25519", bytes: input.publicKey },
    address: base58.encode(input.publicKey),
  });
  return new SvmAccountImpl(inner, keypair);
}

export type { SvmAccount } from "../../hd/account.ts";
