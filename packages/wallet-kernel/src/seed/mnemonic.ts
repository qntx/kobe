import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";

import { KernelError } from "../errors.ts";

const WORD_COUNTS = new Set([12, 15, 18, 21, 24]);
const ENTROPY_LENGTHS = new Set([16, 20, 24, 28, 32]);

/** NFKD, trim, collapse whitespace runs to one space, lowercase. */
export function normalizeMnemonic(text: string): string {
  return text.normalize("NFKD").trim().replaceAll(/\s+/g, " ").toLowerCase();
}

/** Normalized BIP-39 (english wordlist, checksum enforced) → entropy. */
export function entropyFromMnemonic(text: string): Uint8Array {
  const mnemonic = normalizeMnemonic(text);
  if (!WORD_COUNTS.has(mnemonic.split(" ").length)) {
    throw new KernelError("invalid-input", "mnemonic must have 12, 15, 18, 21 or 24 words");
  }
  if (!validateMnemonic(mnemonic, wordlist)) {
    throw new KernelError("invalid-input", "invalid mnemonic");
  }
  return mnemonicToEntropy(mnemonic, wordlist);
}

/** 16/20/24/28/32 bytes of entropy → BIP-39 mnemonic (english wordlist). */
export function mnemonicFromEntropy(entropy: Uint8Array): string {
  if (!ENTROPY_LENGTHS.has(entropy.length)) {
    throw new KernelError("invalid-input", "entropy must be 16, 20, 24, 28 or 32 bytes");
  }
  return entropyToMnemonic(entropy, wordlist);
}
