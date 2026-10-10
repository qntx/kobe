/**
 * Multilingual BIP-39 surface (`wallet/hd/wordlists`).
 * Default `wallet/hd` stays English-only so unused lists tree-shake.
 */
import {
  entropyToMnemonic,
  generateMnemonic,
  mnemonicToEntropy,
  validateMnemonic,
} from "@scure/bip39";
import { wordlist as czech } from "@scure/bip39/wordlists/czech.js";
import { wordlist as english } from "@scure/bip39/wordlists/english.js";
import { wordlist as french } from "@scure/bip39/wordlists/french.js";
import { wordlist as italian } from "@scure/bip39/wordlists/italian.js";
import { wordlist as japanese } from "@scure/bip39/wordlists/japanese.js";
import { wordlist as korean } from "@scure/bip39/wordlists/korean.js";
import { wordlist as portuguese } from "@scure/bip39/wordlists/portuguese.js";
import { wordlist as simplifiedChinese } from "@scure/bip39/wordlists/simplified-chinese.js";
import { wordlist as spanish } from "@scure/bip39/wordlists/spanish.js";
import { wordlist as traditionalChinese } from "@scure/bip39/wordlists/traditional-chinese.js";
import { DeriveError } from "../errors/derive.ts";
import { wipeBytes } from "../secret/dispose.ts";
import { expandMnemonicWith } from "./expand.ts";
import { MNEMONIC_LANGUAGES, type MnemonicLanguage, parseMnemonicLanguage } from "./language.ts";
import {
  buildWalletWith,
  type GenerateWalletOptions,
  type Wallet,
  type WordCount,
} from "./wallet.ts";

const LISTS: Record<MnemonicLanguage, readonly string[]> = {
  english,
  japanese,
  korean,
  spanish,
  french,
  italian,
  czech,
  portuguese,
  "simplified-chinese": simplifiedChinese,
  "traditional-chinese": traditionalChinese,
};

const WORD_COUNT_TO_STRENGTH: Record<WordCount, number> = {
  12: 128,
  15: 160,
  18: 192,
  21: 224,
  24: 256,
};

const ENTROPY_LENS = new Set([16, 20, 24, 28, 32]);

export { MNEMONIC_LANGUAGES, parseMnemonicLanguage, type MnemonicLanguage };

export function wordlistFor(language: MnemonicLanguage): readonly string[] {
  return LISTS[language];
}

export function expandMnemonicIn(language: MnemonicLanguage, phrase: string): string {
  return expandMnemonicWith(wordlistFor(language), phrase);
}

export function isValidMnemonicIn(language: MnemonicLanguage, phrase: string): boolean {
  const normalized = phrase.trim().split(/\s+/).filter(Boolean).join(" ");
  return validateMnemonic(normalized, wordlistFor(language) as string[]);
}

export function generateWalletIn(
  language: MnemonicLanguage,
  opts: GenerateWalletOptions = {},
): Wallet {
  const wordCount = opts.wordCount ?? 12;
  const strength = WORD_COUNT_TO_STRENGTH[wordCount];
  if (strength === undefined) {
    throw new DeriveError("input", `invalid wordCount ${String(opts.wordCount)}`);
  }
  const list = wordlistFor(language) as string[];
  const passphrase = opts.passphrase ?? "";
  let phrase: string;
  if (opts.rng) {
    const entropy = new Uint8Array(strength / 8);
    opts.rng(entropy);
    phrase = entropyToMnemonic(entropy, list);
    wipeBytes(entropy);
  } else {
    phrase = generateMnemonic(list, strength);
  }
  return buildWalletWith(phrase, passphrase, list, language);
}

export function walletFromMnemonicIn(
  language: MnemonicLanguage,
  phrase: string,
  passphrase = "",
): Wallet {
  try {
    return buildWalletWith(phrase, passphrase, wordlistFor(language), language);
  } catch (e) {
    if (e instanceof DeriveError) throw e;
    throw new DeriveError("mnemonic", e instanceof Error ? e.message : "invalid mnemonic", {
      cause: e,
    });
  }
}

export function walletFromMnemonicExpandedIn(
  language: MnemonicLanguage,
  phrase: string,
  passphrase = "",
): Wallet {
  return walletFromMnemonicIn(language, expandMnemonicIn(language, phrase), passphrase);
}

export function walletFromEntropyIn(
  language: MnemonicLanguage,
  entropy: Uint8Array,
  passphrase = "",
): Wallet {
  if (!ENTROPY_LENS.has(entropy.length)) {
    throw new DeriveError("input", `entropy length must be 16|20|24|28|32, got ${entropy.length}`);
  }
  try {
    const list = wordlistFor(language) as string[];
    const phrase = entropyToMnemonic(entropy, list);
    return buildWalletWith(phrase, passphrase, list, language);
  } catch (e) {
    if (e instanceof DeriveError) throw e;
    throw new DeriveError("mnemonic", e instanceof Error ? e.message : "invalid entropy", {
      cause: e,
    });
  }
}

export function mnemonicToEntropyBytesIn(language: MnemonicLanguage, phrase: string): Uint8Array {
  const normalized = phrase.trim().split(/\s+/).filter(Boolean).join(" ");
  const list = wordlistFor(language) as string[];
  if (!validateMnemonic(normalized, list)) {
    throw new DeriveError("mnemonic", "invalid mnemonic checksum or words");
  }
  return mnemonicToEntropy(normalized, list);
}
