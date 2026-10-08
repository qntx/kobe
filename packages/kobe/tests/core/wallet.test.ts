import { inspect } from "node:util";

import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vite-plus/test";

import { expandMnemonic, isValidMnemonic, KobeError, Wallet } from "../../src/core/index.ts";
import type { GenerateWalletOptions, WordCount } from "../../src/core/index.ts";
import { walletSeed } from "../../src/core/wallet.ts";

const ABANDON =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const SEED_HEX_ABANDON =
  "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

/** Run `f`, returning the thrown `KobeError.code`; sentinels keep assertions unconditional. */
function codeOf(f: () => unknown): string {
  try {
    f();
  } catch (error) {
    return error instanceof KobeError ? error.code : "<non-KobeError thrown>";
  }
  return "<no error thrown>";
}

describe("Wallet", () => {
  test("fromMnemonic exposes metadata and normalizes whitespace", () => {
    const w = Wallet.fromMnemonic(`  ${ABANDON.replaceAll(" ", "  ")}  `);
    expect(w.mnemonic()).toBe(ABANDON);
    expect(w.wordCount).toBe(12);
    expect(w.hasPassphrase).toBe(false);
    expect(new TextDecoder().decode(w.mnemonicBytes())).toBe(ABANDON);
    w.dispose();
  });

  test("hasPassphrase reflects a non-empty passphrase", () => {
    const a = Wallet.fromMnemonic(ABANDON, "TREZOR");
    expect(a.hasPassphrase).toBe(true);
    a.dispose();
  });

  test("generate honours wordCount and produces a valid mnemonic", () => {
    for (const wordCount of [12, 24] as const) {
      const w = Wallet.generate({ wordCount });
      expect(w.wordCount).toBe(wordCount);
      expect(isValidMnemonic(w.mnemonic())).toBe(true);
      w.dispose();
    }
  });

  test("generate with injected rng is deterministic", () => {
    const rng = (bytes: Uint8Array): void => {
      bytes.fill(0);
    };
    const w = Wallet.generate({ rng });
    expect(w.mnemonic()).toBe(ABANDON);
    const w24 = Wallet.generate({ wordCount: 24, rng });
    expect(w24.wordCount).toBe(24);
    w.dispose();
    w24.dispose();
  });

  test("generate rejects an invalid wordCount with input", () => {
    const options: GenerateWalletOptions = { wordCount: 13 as WordCount };
    expect(codeOf(() => Wallet.generate(options))).toBe("input");
  });

  test("fromMnemonicExpanded expands 4-letter prefixes", () => {
    const w = Wallet.fromMnemonicExpanded(
      "aban aban aban aban aban aban aban aban aban aban aban abou",
    );
    expect(w.mnemonic()).toBe(ABANDON);
    w.dispose();
    expect(expandMnemonic("abil acti")).toBe("ability action");
  });

  test("dispose is idempotent; secret accessors throw input after dispose", () => {
    const w = Wallet.fromMnemonic(ABANDON);
    w.dispose();
    w.dispose();
    for (const f of [
      () => w.mnemonic(),
      () => w.mnemonicBytes(),
      () => w.deriveSecp256k1("m/44'/60'/0'/0/0"),
      () => walletSeed(w),
    ]) {
      expect(codeOf(f)).toBe("input");
    }
  });

  test("toString / JSON / inspect never leak mnemonic or seed", () => {
    const w = Wallet.fromMnemonic(ABANDON);
    expect(w.toString()).toBe("Wallet [REDACTED]");
    expect(JSON.stringify(w)).not.toContain("abandon");
    // `util.inspect` hides private state (the secrets live in a WeakMap).
    expect(inspect(w)).not.toContain("abandon");
    expect(inspect(w)).not.toContain(SEED_HEX_ABANDON);
    w.dispose();
  });

  test("passphrase changes the seed", () => {
    const a = Wallet.fromMnemonic(ABANDON, "");
    const b = Wallet.fromMnemonic(ABANDON, "TREZOR");
    expect(bytesToHex(walletSeed(a))).not.toBe(bytesToHex(walletSeed(b)));
    expect(bytesToHex(walletSeed(a))).toBe(SEED_HEX_ABANDON);
    a.dispose();
    b.dispose();
  });

  test("walletSeed returns an owned copy", () => {
    const w = Wallet.fromMnemonic(ABANDON);
    const seed = walletSeed(w);
    seed.fill(0);
    expect(bytesToHex(walletSeed(w))).toBe(SEED_HEX_ABANDON);
    w.dispose();
  });

  test("walletSeed rejects an instance that never registered secrets", () => {
    const impostor = Object.create(Wallet.prototype) as Wallet;
    expect(codeOf(() => walletSeed(impostor))).toBe("input");
  });

  test("mnemonicBytes returns an owned copy", () => {
    const w = Wallet.fromMnemonic(ABANDON);
    const bytes = w.mnemonicBytes();
    bytes.fill(0);
    expect(w.mnemonic()).toBe(ABANDON);
    w.dispose();
  });

  test("isValidMnemonic accepts the normalized form only", () => {
    expect(isValidMnemonic(ABANDON)).toBe(true);
    expect(isValidMnemonic(`  ${ABANDON} `)).toBe(true);
    expect(isValidMnemonic("not a mnemonic")).toBe(false);
    expect(isValidMnemonic(ABANDON.replace("about", "ABOUT"))).toBe(false);
  });
});
