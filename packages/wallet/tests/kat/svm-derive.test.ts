import { inspect } from "node:util";

import { expect, test } from "vite-plus/test";

import { createSvmDeriver, parseSvmStyle, svmPath } from "../../src/chains/svm/index.ts";
import type { SvmDerivationStyle } from "../../src/chains/svm/index.ts";
import { DeriveError, walletFromMnemonic } from "../../src/hd/index.ts";

const ABANDON =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

test("gold: bip44-change abandon index 0", () => {
  const w = walletFromMnemonic(ABANDON);
  using a = createSvmDeriver(w).derive(0);
  expect(a.path).toBe("m/44'/501'/0'/0'");
  expect(a.address).toBe("HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk");
  expect(a.privateKeyHex()).toBe(
    "37df573b3ac4ad5b522e064e25b63ea16bcbe79d449e81a0268d1047948bb445",
  );
  expect(a.publicKey.kind).toBe("ed25519");
  w.dispose();
});

test("gold: bip44-change abandon index 1", () => {
  const w = walletFromMnemonic(ABANDON);
  using a = createSvmDeriver(w).derive(1);
  expect(a.path).toBe("m/44'/501'/1'/0'");
  expect(a.address).toBe("Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb");
  expect(a.privateKeyHex()).toBe(
    "ba5e7b6e3680b4eb81db8e54c8e466b2e9a899355888403355d858ab985d2fc4",
  );
  w.dispose();
});

// Addresses below were cross-checked against `kobe svm import --style <style>` (Rust kobe-svm).
test("gold: style addresses match kobe-svm", () => {
  const cases: Array<{ style: SvmDerivationStyle; index: number; address: string }> = [
    {
      style: "bip44-change",
      index: 2,
      address: "7WktogJEd2wQ9eH2oWusmcoFTgeYi6rS632UviTBJ2jm",
    },
    { style: "bip44", index: 0, address: "GjJyeC1r2RgkuoCWMyPYkCWSGSGLcz266EaAkLA27AhL" },
    { style: "bip44", index: 1, address: "ANf3TEKFL6jPWjzkndo4CbnNdUNkBk4KHPggJs2nu8Xi" },
    { style: "bip44", index: 2, address: "Ag74i82rUZBTgMGLacCA1ZLnotvAca8CLscXcrG6Nwem" },
    { style: "legacy", index: 0, address: "DaYoLHpp7RRyAqn1HBPZYZpsKVEAmCDWemW18GABpT5" },
    { style: "legacy", index: 1, address: "ekTgus1k38w7YmdsFogu8UVAETSYWoqA6wMxNRVKijU" },
    { style: "legacy", index: 2, address: "HWfcx4yPXWfMuTwf8bWXELHjYpkzKkwwPYCGctPtPJXm" },
  ];
  const w = walletFromMnemonic(ABANDON);
  const d = createSvmDeriver(w);
  for (const c of cases) {
    using a = d.deriveWith(c.style, c.index);
    expect(a.address).toBe(c.address);
    expect(a.path).toBe(svmPath(c.style, c.index));
  }
  w.dispose();
});

test("style path shapes", () => {
  expect(svmPath("bip44-change", 0)).toBe("m/44'/501'/0'/0'");
  expect(svmPath("bip44", 1)).toBe("m/44'/501'/1'");
  expect(svmPath("legacy", 0)).toBe("m/501'/0'/0'/0'");
});

test("parseSvmStyle aliases", () => {
  for (const [token, style] of [
    ["Phantom", "bip44-change"],
    ["standard", "bip44-change"],
    ["backpack", "bip44-change"],
    ["solflare", "bip44-change"],
    ["trezor", "bip44-change"],
    ["bip44", "bip44"],
    ["trust", "bip44"],
    ["trustwallet", "bip44"],
    ["ledger", "bip44"],
    ["ledger-live", "bip44"],
    ["ledgerlive", "bip44"],
    ["live", "bip44"],
    ["keystone", "bip44"],
    ["sollet", "legacy"],
    ["old", "legacy"],
  ] as const) {
    expect(parseSvmStyle(token)).toBe(style);
  }
  expect(() => parseSvmStyle("nope")).toThrow(DeriveError);
});

test("styles produce distinct addresses", () => {
  const w = walletFromMnemonic(ABANDON);
  const d = createSvmDeriver(w);
  const addrs = (["bip44-change", "bip44", "legacy"] as const).map((s) => {
    using a = d.deriveWith(s, 0);
    return a.address;
  });
  expect(new Set(addrs).size).toBe(3);
  w.dispose();
});

test("keypairBase58 redacted; throws after dispose", () => {
  const w = walletFromMnemonic(ABANDON);
  const a = createSvmDeriver(w).derive(0);
  const kp = a.keypairBase58();
  expect(kp.length).toBeGreaterThan(32);
  expect(inspect(a)).toContain("[REDACTED]");
  expect(inspect(a)).not.toContain(kp);
  a.dispose();
  expect(() => a.keypairBase58()).toThrow(DeriveError);
  w.dispose();
});
