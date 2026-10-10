import { expect, test } from "vite-plus/test";

import { bytesToHex } from "../../src/crypto/hex.ts";
import { DeriveError } from "../../src/errors/derive.ts";
import {
  expandMnemonic,
  parseMnemonicLanguage,
  walletFromEntropy,
  walletFromMnemonic,
  walletFromMnemonicExpanded,
} from "../../src/hd/index.ts";
import * as hd from "../../src/hd/index.ts";
import { walletSeedBytes } from "../../src/hd/raw-seed.ts";
import {
  generateWalletIn,
  isValidMnemonicIn,
  walletFromEntropyIn,
  walletFromMnemonicIn,
  wordlistFor,
} from "../../src/hd/wordlists.ts";

const ABANDON =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ABANDON_PREFIX = "aban aban aban aban aban aban aban aban aban aban aban abou";
const JA_ZERO_SEED =
  "646f1a38134c556e948e6daef213609a62915ef568edb07ffa6046c87638b4b140fef2e0c6d7233af640c4a63de6d1a293288058c8ac1d113255d0504e63f301";

test("gold: English 4-letter prefix expand (kobe)", () => {
  expect(expandMnemonic(ABANDON)).toBe(ABANDON);
  expect(expandMnemonic(ABANDON_PREFIX)).toBe(ABANDON);
  expect(expandMnemonic("abil acti addr admi wall wris")).toBe(
    "ability action address admit wall wrist",
  );
  expect(expandMnemonic("zoo art ice")).toBe("zoo art ice");
});

test("expand rejects short/unknown prefixes without echoing the token", () => {
  try {
    expandMnemonic("aba aba aba aba aba aba aba aba aba aba aba aba");
    throw new Error("expected throw");
  } catch (error) {
    expect(error).toBeInstanceOf(DeriveError);
    expect((error as DeriveError).code).toBe("input");
    expect((error as DeriveError).message).toContain("too short");
    expect((error as DeriveError).message).not.toContain("aba");
  }
  try {
    expandMnemonic("aban aban aban aban aban aban aban aban aban aban aban zzzz");
    throw new Error("expected throw");
  } catch (error) {
    expect((error as DeriveError).message).toContain("does not match");
    expect((error as DeriveError).message).not.toContain("zzzz");
  }
});

test("walletFromMnemonicExpanded imports prefixed English", () => {
  using w = walletFromMnemonicExpanded(ABANDON_PREFIX);
  expect(w.mnemonic()).toBe(ABANDON);
  expect(w.language).toBe("english");
});

test("gold: Japanese zero-entropy mnemonic and seed", () => {
  using w = walletFromEntropyIn("japanese", new Uint8Array(16));
  expect(w.language).toBe("japanese");
  expect(w.wordCount).toBe(12);
  expect(w.mnemonic().split(/\s+/)[0]).toBe("あいこくしん");
  expect(bytesToHex(walletSeedBytes(w))).toBe(JA_ZERO_SEED);
  expect(isValidMnemonicIn("japanese", w.mnemonic())).toBe(true);
  expect(isValidMnemonicIn("english", w.mnemonic())).toBe(false);
});

test("same entropy, different language, different mnemonic", () => {
  using en = walletFromEntropy(new Uint8Array(16));
  using es = walletFromEntropyIn("spanish", new Uint8Array(16));
  expect(en.mnemonic()).toBe(ABANDON);
  expect(es.language).toBe("spanish");
  expect(es.mnemonic()).not.toBe(en.mnemonic());
  expect(bytesToHex(walletSeedBytes(es))).not.toBe(bytesToHex(walletSeedBytes(en)));
});

test("walletFromMnemonicIn rejects the English phrase as Japanese", () => {
  expect(() => walletFromMnemonicIn("japanese", ABANDON)).toThrow(DeriveError);
  using w = walletFromMnemonic(ABANDON);
  expect(w.language).toBe("english");
});

test("generateWalletIn japanese is 12 valid words", () => {
  using w = generateWalletIn("japanese", { wordCount: 12 });
  expect(w.language).toBe("japanese");
  expect(w.mnemonic().split(/\s+/)).toHaveLength(12);
  expect(isValidMnemonicIn("japanese", w.mnemonic())).toBe(true);
  expect(wordlistFor("japanese")).toHaveLength(2048);
});

test("parseMnemonicLanguage aliases; unknown throws", () => {
  expect(parseMnemonicLanguage("JA")).toBe("japanese");
  expect(parseMnemonicLanguage("zh-hans")).toBe("simplified-chinese");
  expect(() => parseMnemonicLanguage("klingon")).toThrow(DeriveError);
});

test("wallet/hd barrel does not export wordlistFor", () => {
  expect("wordlistFor" in hd).toBe(false);
  expect("generateWalletIn" in hd).toBe(false);
});
