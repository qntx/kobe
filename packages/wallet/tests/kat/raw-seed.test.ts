import { expect, test } from "vite-plus/test";

import { bytesToHex } from "../../src/crypto/hex.ts";
import { DeriveError, walletFromMnemonic } from "../../src/hd/index.ts";
import * as hd from "../../src/hd/index.ts";
import { walletSeedBytes } from "../../src/hd/raw-seed.ts";

const ABANDON =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const SEED_HEX_ABANDON =
  "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

test("gold: walletSeedBytes abandon empty passphrase (BIP-39 / kobe)", () => {
  const w = walletFromMnemonic(ABANDON);
  expect(bytesToHex(walletSeedBytes(w))).toBe(SEED_HEX_ABANDON);
  expect(walletSeedBytes(w)).toHaveLength(64);
  w.dispose();
});

test("walletSeedBytes copy is independent; dispose throws", () => {
  const w = walletFromMnemonic(ABANDON);
  const a = walletSeedBytes(w);
  const b = walletSeedBytes(w);
  expect(a).toEqual(b);
  expect(a).not.toBe(b);
  a[0] = 255 - (a[0] ?? 0);
  expect(walletSeedBytes(w)[0]).not.toBe(a[0]);
  w.dispose();
  expect(() => walletSeedBytes(w)).toThrow(DeriveError);
});

test("passphrase changes seed", () => {
  const a = walletFromMnemonic(ABANDON, "");
  const b = walletFromMnemonic(ABANDON, "TREZOR");
  expect(bytesToHex(walletSeedBytes(a))).not.toBe(bytesToHex(walletSeedBytes(b)));
  a.dispose();
  b.dispose();
});

test("wallet/hd barrel does not export walletSeedBytes", () => {
  expect("walletSeedBytes" in hd).toBe(false);
});
