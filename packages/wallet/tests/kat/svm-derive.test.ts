import { inspect } from "node:util";
import { expect, test } from "vitest";
import { createSvmDeriver, parseSvmStyle, svmPath } from "../../src/chains/svm/index.ts";
import { DeriveError, walletFromMnemonic } from "../../src/hd/index.ts";

const ABANDON =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

test("gold: Phantom abandon index 0", () => {
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

test("gold: Phantom abandon index 1", () => {
  const w = walletFromMnemonic(ABANDON);
  using a = createSvmDeriver(w).derive(1);
  expect(a.path).toBe("m/44'/501'/1'/0'");
  expect(a.address).toBe("Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb");
  expect(a.privateKeyHex()).toBe(
    "ba5e7b6e3680b4eb81db8e54c8e466b2e9a899355888403355d858ab985d2fc4",
  );
  w.dispose();
});

test("style path shapes", () => {
  expect(svmPath("standard", 0)).toBe("m/44'/501'/0'/0'");
  expect(svmPath("trust", 1)).toBe("m/44'/501'/1'");
  expect(svmPath("ledger-live", 0)).toBe("m/44'/501'/0'/0'/0'");
  expect(svmPath("legacy", 0)).toBe("m/501'/0'/0'/0'");
});

test("parseSvmStyle aliases", () => {
  expect(parseSvmStyle("Phantom")).toBe("standard");
  expect(parseSvmStyle("keystone")).toBe("trust");
  expect(parseSvmStyle("sollet")).toBe("legacy");
  expect(() => parseSvmStyle("nope")).toThrow(DeriveError);
});

test("styles produce distinct addresses", () => {
  const w = walletFromMnemonic(ABANDON);
  const d = createSvmDeriver(w);
  const addrs = (["standard", "trust", "ledger-live", "legacy"] as const).map((s) => {
    using a = d.deriveWith(s, 0);
    return a.address;
  });
  expect(new Set(addrs).size).toBe(4);
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
