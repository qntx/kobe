import { expect, test } from "vite-plus/test";

import { DeriveError } from "../../src/errors/derive.ts";
import { decrypt, encrypt } from "../../src/hd/camouflage.ts";
import { isValidMnemonic, walletFromMnemonic } from "../../src/hd/index.ts";
import * as hd from "../../src/hd/index.ts";

const TEST_12 =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const TEST_24 =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
const PASSWORD = "my-secret-password-2024";
/** Python hashlib PBKDF2-HMAC-SHA256 + @scure entropyToMnemonic (zero entropy XOR key). */
const GOLD_12 = "weasel chase romance unfold member patrol tip short defy remove glide creek";

test("gold: v1 camouflage of abandon 12-word (kobe salt/iter + hashlib)", () => {
  expect(encrypt(TEST_12, PASSWORD)).toBe(GOLD_12);
  expect(decrypt(GOLD_12, PASSWORD)).toBe(TEST_12);
}, 30_000);

test("24-word round-trip; camouflage is a valid mnemonic", () => {
  const camouflaged = encrypt(TEST_24, PASSWORD);
  expect(camouflaged).not.toBe(TEST_24);
  expect(isValidMnemonic(camouflaged)).toBe(true);
  expect(decrypt(camouflaged, PASSWORD)).toBe(TEST_24);
  using w = walletFromMnemonic(camouflaged);
  expect(w.wordCount).toBe(24);
}, 30_000);

test("empty password rejected; wrong password does not recover", () => {
  expect(() => encrypt(TEST_12, "")).toThrow(DeriveError);
  const camouflaged = encrypt(TEST_12, PASSWORD);
  expect(decrypt(camouflaged, "wrong-password")).not.toBe(TEST_12);
}, 30_000);

test("wallet/hd barrel does not export camouflage", () => {
  expect("encrypt" in hd).toBe(false);
  expect("decrypt" in hd).toBe(false);
});
