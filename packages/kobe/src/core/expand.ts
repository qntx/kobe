import { wordlist as english } from "@scure/bip39/wordlists/english.js";

import { KobeError } from "./error.ts";

const MIN_PREFIX_LEN = 4;

function resolveToken(list: ReadonlyArray<string>, token: string): string {
  const matches: string[] = [];
  for (const word of list) {
    if (word === token) {
      return word;
    }
    if (word.startsWith(token)) {
      matches.push(word);
    }
  }

  // Error messages deliberately omit the raw token so stderr / JSON errors do
  // not re-echo partial secret material from failed imports.
  if (token.length < MIN_PREFIX_LEN) {
    throw new KobeError(
      "input",
      `mnemonic: word prefix is too short (minimum ${MIN_PREFIX_LEN} characters)`,
    );
  }
  const [only] = matches;
  if (matches.length === 1 && only !== undefined) {
    return only;
  }
  if (matches.length === 0) {
    throw new KobeError("input", "mnemonic: word prefix does not match any BIP-39 word");
  }
  throw new KobeError(
    "input",
    `mnemonic: word prefix is ambiguous (matches ${matches.length} BIP-39 words)`,
  );
}

/**
 * Expand abbreviated words in a mnemonic phrase to their full BIP-39 English form
 * (`kobe_core::mnemonic::expand` analog).
 *
 * Each whitespace-separated token is matched against the English wordlist: an exact match is kept
 * as-is, a prefix of at least 4 characters that uniquely identifies one word is expanded,
 * everything else throws.
 *
 * @throws KobeError input if a token resolves to zero or multiple words, or a non-exact token is
 *   shorter than 4 characters
 */
export function expandMnemonic(phrase: string): string {
  const tokens = phrase.trim().split(/\s+/).filter(Boolean);
  return tokens.map((token) => resolveToken(english, token)).join(" ");
}
