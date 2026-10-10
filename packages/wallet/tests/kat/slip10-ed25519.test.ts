import { expect, test } from "vite-plus/test";

import { hexToBytes } from "../../src/crypto/hex.ts";
import { DeriveError, walletFromMnemonic } from "../../src/hd/index.ts";
import { deriveEd25519FromSeed } from "../../src/slip10/index.ts";

const ABANDON =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// SLIP-0010 vector 1 seed
const SLIP_SEED = hexToBytes("000102030405060708090a0b0c0d0e0f");

test("gold: SLIP-10 master key from vector seed", () => {
  using key = deriveEd25519FromSeed(SLIP_SEED, "m");
  expect(key.privateKeyHex()).toBe(
    "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
  );
});

test("gold: SLIP-10 m/0' from vector seed", () => {
  using key = deriveEd25519FromSeed(SLIP_SEED, "m/0'");
  expect(key.privateKeyHex()).toBe(
    "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
  );
});

test("gold: Solana standard path index 0 from abandon (kobe-svm)", () => {
  const w = walletFromMnemonic(ABANDON);
  using key = w.deriveEd25519("m/44'/501'/0'/0'");
  expect(key.privateKeyHex()).toBe(
    "37df573b3ac4ad5b522e064e25b63ea16bcbe79d449e81a0268d1047948bb445",
  );
  expect(key.publicKeyBytes()).toHaveLength(32);
  w.dispose();
});

test("gold: Solana standard path index 1 from abandon (kobe-svm)", () => {
  const w = walletFromMnemonic(ABANDON);
  using key = w.deriveEd25519("m/44'/501'/1'/0'");
  expect(key.privateKeyHex()).toBe(
    "ba5e7b6e3680b4eb81db8e54c8e466b2e9a899355888403355d858ab985d2fc4",
  );
  w.dispose();
});

test("rejects non-hardened path segments", () => {
  const w = walletFromMnemonic(ABANDON);
  expect(() => w.deriveEd25519("m/44'/501'/0'/0")).toThrow(DeriveError);
  try {
    w.deriveEd25519("m/44'/501'/0'/0");
  } catch (error) {
    expect((error as DeriveError).code).toBe("path");
  }
  w.dispose();
});
