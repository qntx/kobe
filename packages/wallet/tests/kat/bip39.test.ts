import { inspect } from "node:util";

import { expect, test } from "vite-plus/test";

import { bytesToHex } from "../../src/crypto/hex.ts";
import {
  DeriveError,
  generateWallet,
  isValidMnemonic,
  walletFromEntropy,
  walletFromMnemonic,
} from "../../src/hd/index.ts";
import { walletSeedBytes } from "../../src/hd/raw-seed.ts";

const ABANDON =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const SEED_HEX_ABANDON =
  "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

test("gold: abandon…about empty passphrase seed (BIP-39 / kobe)", () => {
  const w = walletFromMnemonic(ABANDON);
  expect(w.mnemonic()).toBe(ABANDON);
  expect(w.wordCount).toBe(12);
  expect(w.hasPassphrase).toBe(false);
  const again = walletFromMnemonic(ABANDON, "");
  expect(again.mnemonic()).toBe(ABANDON);
  expect(bytesToHex(walletSeedBytes(w))).toBe(SEED_HEX_ABANDON);
  again.dispose();
  w.dispose();
});

test("all-zero entropy produces abandon…about", () => {
  const w = walletFromEntropy(new Uint8Array(16));
  expect(w.mnemonic()).toBe(ABANDON);
  w.dispose();
});

test("invalid mnemonic throws DeriveError mnemonic", () => {
  expect(() => walletFromMnemonic("not a valid mnemonic phrase at all")).toThrow(DeriveError);
  try {
    walletFromMnemonic("not a valid mnemonic phrase at all junk words here");
  } catch (error) {
    expect(error).toBeInstanceOf(DeriveError);
    expect((error as DeriveError).code).toBe("mnemonic");
  }
});

test("bad entropy length throws input", () => {
  expect(() => walletFromEntropy(new Uint8Array(15))).toThrow(DeriveError);
  try {
    walletFromEntropy(new Uint8Array(15));
  } catch (error) {
    expect((error as DeriveError).code).toBe("input");
  }
});

test("generateWallet 12 words is valid", () => {
  const w = generateWallet({ wordCount: 12 });
  expect(w.wordCount).toBe(12);
  expect(isValidMnemonic(w.mnemonic())).toBe(true);
  w.dispose();
});

test("dispose is idempotent; secret accessors throw after dispose", () => {
  const w = walletFromMnemonic(ABANDON);
  w.dispose();
  w.dispose();
  expect(() => w.mnemonic()).toThrow(DeriveError);
  expect(() => w.mnemonicBytes()).toThrow(DeriveError);
});

test("inspect / JSON redacts secrets", () => {
  const w = walletFromMnemonic(ABANDON);
  expect(JSON.stringify(w)).not.toContain("abandon");
  expect(w.toString()).toBe("Wallet [REDACTED]");
  expect(inspect(w)).toContain("REDACTED");
  expect(inspect(w)).not.toContain("abandon");
  w.dispose();
});

test("passphrase changes seed", () => {
  const a = walletFromMnemonic(ABANDON, "");
  const b = walletFromMnemonic(ABANDON, "TREZOR");
  expect(bytesToHex(walletSeedBytes(a))).not.toBe(bytesToHex(walletSeedBytes(b)));
  a.dispose();
  b.dispose();
});
