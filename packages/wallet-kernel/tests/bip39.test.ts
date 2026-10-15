import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vite-plus/test";

import {
  entropyFromMnemonic,
  mnemonicFromEntropy,
  normalizeMnemonic,
} from "../src/seed/mnemonic.ts";
import { seedFromEntropy, seedFromMnemonic } from "../src/seed/seed.ts";
import { kernelError, loadVectors, subtlePbkdf2 } from "./helpers.ts";

// Each entry: [entropy hex, mnemonic, seed hex, xprv]. Passphrase "TREZOR".
type Bip39Vector = [entropy: string, mnemonic: string, seed: string, xprv: string];
const { english } = loadVectors("bip39.json") as { english: Bip39Vector[] };

describe("subtlePbkdf2", () => {
  it("matches @noble/hashes pbkdf2", async () => {
    const password = new Uint8Array([1, 2, 3]);
    const salt = new Uint8Array([4, 5, 6]);
    await expect(subtlePbkdf2("sha256", password, salt, 7, 32)).resolves.toStrictEqual(
      pbkdf2(sha256, password, salt, { c: 7, dkLen: 32 }),
    );
    await expect(subtlePbkdf2("sha512", password, salt, 7, 64)).resolves.toStrictEqual(
      pbkdf2(sha512, password, salt, { c: 7, dkLen: 64 }),
    );
  });
});

describe("bip39 vectors", () => {
  it.each(english)("entropy ⇄ mnemonic ⇄ seed: %s", async (entropy, mnemonic, seed) => {
    expect(bytesToHex(entropyFromMnemonic(mnemonic))).toBe(entropy);
    expect(mnemonicFromEntropy(hexToBytes(entropy))).toBe(mnemonic);
    await expect(seedFromMnemonic(mnemonic, "TREZOR", subtlePbkdf2)).resolves.toStrictEqual(
      hexToBytes(seed),
    );
    await expect(seedFromEntropy(hexToBytes(entropy), subtlePbkdf2)).resolves.toStrictEqual(
      await seedFromMnemonic(mnemonic, "", subtlePbkdf2),
    );
  });
});

describe("normalizeMnemonic", () => {
  it("collapses extra whitespace and lowercases", () => {
    const [, mnemonic] = english[0]!;
    const messy = `  ${mnemonic.split(" ").join("   \t\n")}  `.toUpperCase();
    expect(normalizeMnemonic(messy)).toBe(mnemonic);
    expect(entropyFromMnemonic(messy)).toStrictEqual(entropyFromMnemonic(mnemonic));
  });
});

describe("entropyFromMnemonic rejects", () => {
  it("bad checksum", () => {
    const mnemonic = `${english[0]![1].split(" ").slice(0, -1).join(" ")} abandon`;
    expect(kernelError(() => entropyFromMnemonic(mnemonic))).toBe("invalid-input");
  });

  it("wrong word count", () => {
    const mnemonic = english[0]![1].split(" ").slice(0, 11).join(" ");
    expect(kernelError(() => entropyFromMnemonic(mnemonic))).toBe("invalid-input");
  });

  it("word outside the english wordlist", () => {
    const words = english[0]![1].split(" ");
    words[3] = "notaword";
    expect(kernelError(() => entropyFromMnemonic(words.join(" ")))).toBe("invalid-input");
  });
});

describe("mnemonicFromEntropy rejects", () => {
  it("unsupported entropy length", () => {
    expect(kernelError(() => mnemonicFromEntropy(new Uint8Array(8)))).toBe("invalid-input");
  });
});
