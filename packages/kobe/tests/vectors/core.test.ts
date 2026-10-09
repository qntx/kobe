import { readFileSync } from "node:fs";
import { join } from "node:path";

import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { base58 } from "@scure/base";
import { describe, expect, test } from "vite-plus/test";

import { deriveSecp256k1FromSeed } from "../../src/core/bip32.ts";
import { KobeError } from "../../src/core/error.ts";
import { expandMnemonic } from "../../src/core/expand.ts";
import { Wallet, walletSeed } from "../../src/core/wallet.ts";

const root = join(import.meta.dirname, "../../../../vectors");

const TREZOR = JSON.parse(readFileSync(join(root, "bip39/trezor.json"), "utf8")) as {
  english: Array<[entropy: string, mnemonic: string, seed: string, xprv: string]>;
};
const BIP39 = JSON.parse(readFileSync(join(root, "core/bip39.json"), "utf8")) as {
  cases: Array<{
    input?: string;
    mnemonic?: string;
    passphrase?: string;
    entropy?: string;
    seed?: string;
    wordCount?: number;
    error?: string;
  }>;
};
const BIP32 = JSON.parse(readFileSync(join(root, "core/bip32.json"), "utf8")) as {
  cases: Array<{
    mnemonic: string;
    passphrase?: string;
    path: string;
    privateKey?: string;
    compressedPublicKey?: string;
    uncompressedPublicKey?: string;
    error?: string;
  }>;
};
const BIP32_OFFICIAL = JSON.parse(readFileSync(join(root, "bip32/official.json"), "utf8")) as {
  cases: Array<{ seed: string; chains: Array<{ path: string; xpub: string; xprv: string }> }>;
};
const MNEMONIC_EXPAND = JSON.parse(
  readFileSync(join(root, "core/mnemonic-expand.json"), "utf8"),
) as { cases: Array<{ input: string; mnemonic?: string; error?: string }> };
const WALLET_ID = JSON.parse(readFileSync(join(root, "core/wallet-id.json"), "utf8")) as {
  cases: Array<{ mnemonic: string; passphrase?: string; masterPublicKey: string; id: string }>;
};

/** Run `f`, returning the thrown `KobeError.code`; sentinels keep assertions unconditional. */
function codeOf(f: () => unknown): string {
  try {
    f();
  } catch (error) {
    return error instanceof KobeError ? error.code : "<non-KobeError thrown>";
  }
  return "<no error thrown>";
}

// Case partitions are computed outside the test callbacks: `??`, `||` and
// ternaries inside `test` are rejected by the no-conditional-in-test lint.
const bip39Valid = BIP39.cases.filter((c) => c.error === undefined && c.entropy !== undefined);
const bip39Normalize = bip39Valid
  .filter((c) => c.input !== undefined)
  .map((c) => ({ input: c.input ?? "", mnemonic: c.mnemonic ?? "" }));
const bip39EntropyCases = bip39Valid
  .filter((c) => c.input === undefined)
  .map((c) => ({
    entropy: c.entropy ?? "",
    mnemonic: c.mnemonic ?? "",
    passphrase: c.passphrase ?? "",
    seed: c.seed ?? "",
    wordCount: c.wordCount ?? 0,
  }));
const bip39PhraseErrors = BIP39.cases
  .filter((c) => c.input !== undefined && c.error !== undefined)
  .map((c) => ({ input: c.input ?? "", error: c.error ?? "" }));
const bip39EntropyErrors = BIP39.cases
  .filter((c) => c.input === undefined && c.error !== undefined)
  .map((c) => ({ entropy: c.entropy ?? "", error: c.error ?? "" }));

const bip32Cases = BIP32.cases.map((c) => ({ ...c, passphrase: c.passphrase ?? "" }));
const bip32Valid = bip32Cases.filter((c) => c.error === undefined);
const bip32Invalid = bip32Cases.filter((c) => c.error !== undefined);

const expandValid = MNEMONIC_EXPAND.cases.filter((c) => c.error === undefined);
const expandInvalid = MNEMONIC_EXPAND.cases.filter((c) => c.error !== undefined);

const walletIdCases = WALLET_ID.cases.map((c) => ({ ...c, passphrase: c.passphrase ?? "" }));

describe("vectors/bip39/trezor.json", () => {
  test("entropy → mnemonic and mnemonic → seed (passphrase TREZOR)", () => {
    expect(TREZOR.english.length).toBeGreaterThan(0);
    for (const [entropy, mnemonic, seed] of TREZOR.english) {
      const wallet = Wallet.fromEntropy(hexToBytes(entropy), "TREZOR");
      expect(wallet.mnemonic()).toBe(mnemonic);
      expect(bytesToHex(walletSeed(wallet))).toBe(seed);
      wallet.dispose();

      const rebuilt = Wallet.fromMnemonic(mnemonic, "TREZOR");
      expect(bytesToHex(walletSeed(rebuilt))).toBe(seed);
      rebuilt.dispose();
    }
  });
});

describe("vectors/core/bip39.json", () => {
  test("entropy → mnemonic, seed and word count", () => {
    for (const c of bip39EntropyCases) {
      const wallet = Wallet.fromEntropy(hexToBytes(c.entropy), c.passphrase);
      expect(wallet.mnemonic()).toBe(c.mnemonic);
      expect(wallet.wordCount).toBe(c.wordCount);
      expect(bytesToHex(walletSeed(wallet))).toBe(c.seed);
      wallet.dispose();

      const rebuilt = Wallet.fromMnemonic(c.mnemonic, c.passphrase);
      expect(bytesToHex(walletSeed(rebuilt))).toBe(c.seed);
      rebuilt.dispose();
    }
  });

  test("whitespace normalization", () => {
    for (const c of bip39Normalize) {
      const wallet = Wallet.fromMnemonic(c.input);
      expect(wallet.mnemonic()).toBe(c.mnemonic);
      wallet.dispose();
    }
  });

  test("invalid phrases share the error codes", () => {
    for (const c of bip39PhraseErrors) {
      expect(codeOf(() => Wallet.fromMnemonic(c.input))).toBe(c.error);
    }
  });

  test("invalid entropy lengths share the error codes", () => {
    for (const c of bip39EntropyErrors) {
      expect(codeOf(() => Wallet.fromEntropy(hexToBytes(c.entropy)))).toBe(c.error);
    }
  });
});

describe("vectors/core/bip32.json", () => {
  test("derive secp256k1 keys", () => {
    for (const c of bip32Valid) {
      const wallet = Wallet.fromMnemonic(c.mnemonic, c.passphrase);
      const key = wallet.deriveSecp256k1(c.path);
      expect(key.privateKeyHex()).toBe(c.privateKey);
      expect(key.compressedPublicKeyHex()).toBe(c.compressedPublicKey);
      expect(key.uncompressedPublicKeyHex()).toBe(c.uncompressedPublicKey);
      key.dispose();
      wallet.dispose();
    }
  });

  test("malformed paths share the error codes", () => {
    for (const c of bip32Invalid) {
      const wallet = Wallet.fromMnemonic(c.mnemonic, c.passphrase);
      expect(codeOf(() => wallet.deriveSecp256k1(c.path))).toBe(c.error);
      wallet.dispose();
    }
  });
});

describe("vectors/bip32/official.json", () => {
  test("official vectors 1-4 derive xprv/xpub payloads from raw seeds", () => {
    for (const c of BIP32_OFFICIAL.cases) {
      const seed = hexToBytes(c.seed);
      for (const chain of c.chains) {
        const key = deriveSecp256k1FromSeed(seed, chain.path);
        // Base58Check payload only — the checksum is not under test.
        const xprv = base58.decode(chain.xprv);
        const xpub = base58.decode(chain.xpub);
        expect(bytesToHex(key.privateKeyBytes())).toBe(bytesToHex(xprv.slice(46, 78)));
        expect(bytesToHex(key.compressedPublicKey())).toBe(bytesToHex(xpub.slice(45, 78)));
        key.dispose();
      }
    }
  });
});

describe("vectors/core/wallet-id.json", () => {
  test("id = hex(sha256('kobe/wallet-id/v1' ‖ compressed BIP-32 master pubkey))[..16]", () => {
    for (const c of walletIdCases) {
      const wallet = Wallet.fromMnemonic(c.mnemonic, c.passphrase);
      // The master pubkey is pinned separately so a BIP-32 divergence
      // between @scure/bip32 and the Rust `bip32` crate cannot hide in the hash.
      const master = wallet.deriveSecp256k1("m");
      expect(master.compressedPublicKeyHex()).toBe(c.masterPublicKey);
      master.dispose();
      expect(wallet.id()).toBe(c.id);
      wallet.dispose();
    }
  });
});

describe("vectors/core/mnemonic-expand.json", () => {
  test("expand prefixes to full words", () => {
    for (const c of expandValid) {
      expect(expandMnemonic(c.input)).toBe(c.mnemonic);
    }
  });

  test("invalid prefixes share the error codes", () => {
    for (const c of expandInvalid) {
      expect(codeOf(() => expandMnemonic(c.input))).toBe(c.error);
    }
  });
});
