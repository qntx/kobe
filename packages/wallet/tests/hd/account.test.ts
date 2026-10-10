import { inspect } from "node:util";

import { expect, test } from "vite-plus/test";

import { createDerivedAccount, DeriveError, walletFromMnemonic } from "../../src/hd/index.ts";
import type { DerivedAccount } from "../../src/hd/index.ts";

const ABANDON =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const SK_HEX = "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727";
const PK_HEX = "0237b0bb7a8288d38ed49a524b5dc98cff3eb5ca824c9f9dc0dfdb3d9cd600f299";

function sample(): DerivedAccount {
  const w = walletFromMnemonic(ABANDON);
  const key = w.deriveSecp256k1("m/44'/60'/0'/0/0");
  const acct = createDerivedAccount({
    path: "m/44'/60'/0'/0/0",
    privateKey: key.privateKeyBytes(),
    publicKey: {
      kind: "secp256k1-compressed",
      bytes: key.compressedPublicKey(),
    },
    address: "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
  });
  key.dispose();
  w.dispose();
  return acct;
}

test("account snapshots pubkey and copies secret", () => {
  using acct = sample();
  expect(acct.path).toBe("m/44'/60'/0'/0/0");
  expect(acct.privateKeyHex()).toBe(SK_HEX);
  expect(acct.publicKey.kind).toBe("secp256k1-compressed");
  expect(acct.publicKeyHex()).toBe(PK_HEX);
  expect(acct.publicKey.bytes).toHaveLength(33);

  const a = acct.privateKeyBytes();
  const b = acct.privateKeyBytes();
  expect(a).not.toBe(b);
  a.fill(0);
  expect(acct.privateKeyHex()).toBe(SK_HEX);
});

test("dispose zeros secret; path/address/pubkey remain", () => {
  const acct = sample();
  acct.dispose();
  acct.dispose();
  expect(acct.path).toBe("m/44'/60'/0'/0/0");
  expect(acct.address).toContain("0x");
  expect(acct.publicKey.bytes).toHaveLength(33);
  expect(() => acct.privateKeyBytes()).toThrow(DeriveError);
  expect(() => acct.privateKeyHex()).toThrow(DeriveError);
});

test("inspect and JSON redact private key", () => {
  using acct = sample();
  expect(inspect(acct)).toContain("[REDACTED]");
  expect(inspect(acct)).not.toContain(SK_HEX);
  expect(JSON.stringify(acct)).not.toContain(SK_HEX);
  expect(acct.toString()).toContain("[REDACTED]");
});

test("wrong secret length throws crypto", () => {
  expect(() =>
    createDerivedAccount({
      path: "m",
      privateKey: new Uint8Array(31),
      publicKey: { kind: "ed25519", bytes: new Uint8Array(32) },
      address: "x",
    }),
  ).toThrow(DeriveError);
});

test("wrong pubkey length throws crypto", () => {
  expect(() =>
    createDerivedAccount({
      path: "m",
      privateKey: new Uint8Array(32),
      publicKey: { kind: "secp256k1-uncompressed", bytes: new Uint8Array(33) },
      address: "x",
    }),
  ).toThrow(DeriveError);
});
