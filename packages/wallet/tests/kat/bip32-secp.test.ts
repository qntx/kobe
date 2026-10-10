import { expect, test } from "vitest";
import { DeriveError, walletFromMnemonic } from "../../src/hd/index.ts";

const ABANDON =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

test("gold: ethereum path m/44'/60'/0'/0/0 private key (kobe/BIP-32)", () => {
  const w = walletFromMnemonic(ABANDON);
  using key = w.deriveSecp256k1("m/44'/60'/0'/0/0");
  expect(key.privateKeyHex()).toBe(
    "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727",
  );
  expect(key.compressedPublicKeyHex()).toBe(
    "0237b0bb7a8288d38ed49a524b5dc98cff3eb5ca824c9f9dc0dfdb3d9cd600f299",
  );
  expect(key.uncompressedPublicKey()[0]).toBe(0x04);
  expect(key.uncompressedPublicKey().length).toBe(65);
  w.dispose();
});

test("different paths produce different keys", () => {
  const w = walletFromMnemonic(ABANDON);
  const k0 = w.deriveSecp256k1("m/44'/60'/0'/0/0");
  const k1 = w.deriveSecp256k1("m/44'/60'/0'/0/1");
  expect(k0.privateKeyHex()).not.toBe(k1.privateKeyHex());
  k0.dispose();
  k1.dispose();
  w.dispose();
});

test("invalid path rejected", () => {
  const w = walletFromMnemonic(ABANDON);
  expect(() => w.deriveSecp256k1("bad")).toThrow(DeriveError);
  w.dispose();
});

test("derive after wallet dispose throws", () => {
  const w = walletFromMnemonic(ABANDON);
  w.dispose();
  expect(() => w.deriveSecp256k1("m/44'/60'/0'/0/0")).toThrow(DeriveError);
});
