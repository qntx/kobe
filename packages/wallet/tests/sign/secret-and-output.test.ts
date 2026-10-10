import { inspect } from "node:util";

import { expect, test } from "vite-plus/test";

import { createDerivedAccount, walletFromMnemonic } from "../../src/hd/index.ts";
import {
  EIP191_OFFSET,
  secp256k1SignerFromSecret,
  secretKeyFromBytes,
  secretKeyFromDerived,
  secretKeyFromHex,
  SignError,
  signerFromSecret,
  signOutputToBytes,
  withVOffset,
} from "../../src/sign/index.ts";

const ABANDON =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

test("secretKeyFromBytes rejects wrong length", () => {
  expect(() => secretKeyFromBytes(new Uint8Array(31))).toThrow(SignError);
});

test("inspect redacts SecretKey32", () => {
  using key = secretKeyFromHex("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318");
  expect(inspect(key)).toBe("SecretKey32([REDACTED])");
  expect(JSON.stringify(key)).toContain("REDACTED");
});

test("dispose is independent of signer copy", () => {
  const key = secretKeyFromHex("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318");
  const signer = secp256k1SignerFromSecret(key);
  key.dispose();
  key.dispose();
  const digest = new Uint8Array(32).fill(1);
  const out = signer.signPrehashRecoverable(digest);
  expect(out.signature).toHaveLength(64);
  signer.dispose();
  expect(() => signer.signPrehashRecoverable(digest)).toThrow(SignError);
});

test("fromDerived copies; disposing account does not kill signer", () => {
  const w = walletFromMnemonic(ABANDON);
  const derived = w.deriveSecp256k1("m/44'/60'/0'/0/0");
  const acct = createDerivedAccount({
    path: "m/44'/60'/0'/0/0",
    privateKey: derived.privateKeyBytes(),
    publicKey: {
      kind: "secp256k1-compressed",
      bytes: derived.compressedPublicKey(),
    },
    address: "0x0",
  });
  derived.dispose();
  w.dispose();

  const sk = secretKeyFromDerived(acct);
  const signer = secp256k1SignerFromSecret(sk);
  acct.dispose();
  sk.dispose();
  const out = signer.signPrehashRecoverable(new Uint8Array(32).fill(2));
  expect(out.v === 0 || out.v === 1).toBe(true);
  signer.dispose();
});

test("withVOffset adds EIP-191 header", () => {
  const raw = {
    scheme: "ecdsa_recoverable" as const,
    signature: new Uint8Array(64),
    v: 1,
  };
  const offset = withVOffset(raw, EIP191_OFFSET);
  expect(offset.scheme).toBe("ecdsa_recoverable");
  if (offset.scheme === "ecdsa_recoverable") {
    expect(offset.v).toBe(28);
  }
  const wire = signOutputToBytes(offset);
  expect(wire).toHaveLength(65);
  expect(wire[64]).toBe(28);
});

test("zero secp scalar rejected at engine construction", () => {
  using key = secretKeyFromBytes(new Uint8Array(32));
  expect(() => secp256k1SignerFromSecret(key)).toThrow(SignError);
});

test("signerFromSecret fromHex and fromDerived", () => {
  const hex = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
  const factories = signerFromSecret((key) => ({
    len: key.toBytes().length,
    dispose() {},
    [Symbol.dispose]() {},
  }));
  using fromHex = factories.fromHex(hex);
  expect(fromHex.len).toBe(32);

  const w = walletFromMnemonic(ABANDON);
  const derived = w.deriveSecp256k1("m/44'/60'/0'/0/0");
  const acct = createDerivedAccount({
    path: "m/44'/60'/0'/0/0",
    privateKey: derived.privateKeyBytes(),
    publicKey: {
      kind: "secp256k1-compressed",
      bytes: derived.compressedPublicKey(),
    },
    address: "0x0",
  });
  derived.dispose();
  w.dispose();
  using fromDerived = factories.fromDerived(acct);
  acct.dispose();
  expect(fromDerived.len).toBe(32);
});
