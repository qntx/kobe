import { wordlist as english } from "@scure/bip39/wordlists/english.js";

import { DeriveError } from "../errors/derive.ts";

const MIN_PREFIX_LEN = 4;

function resolveToken(list: ReadonlyArray<string>, token: string): string {
  let lo = 0;
  let hi = list.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    const word = list[mid];
    if (word === undefined) {
      throw new DeriveError("crypto", "wordlist index out of range");
    }
    if (word === token) {
      return word;
    }
    if (word < token) {
      lo = mid + 1;
    } else {
      hi = mid;
    }
  }

  if (token.length < MIN_PREFIX_LEN) {
    throw new DeriveError(
      "input",
      `mnemonic: word prefix is too short (minimum ${MIN_PREFIX_LEN} characters)`,
    );
  }

  const matches: string[] = [];
  for (const word of list) {
    if (word.startsWith(token)) {
      matches.push(word);
    }
  }
  if (matches.length === 0) {
    throw new DeriveError("input", "mnemonic: word prefix does not match any BIP-39 word");
  }
  const [only] = matches;
  if (matches.length === 1 && only !== undefined) {
    return only;
  }
  throw new DeriveError(
    "input",
    `mnemonic: word prefix is ambiguous (matches ${matches.length} BIP-39 words)`,
  );
}

/** Expand tokens against an arbitrary BIP-39 wordlist. Does not echo rejected tokens. */
export function expandMnemonicWith(list: ReadonlyArray<string>, phrase: string): string {
  const tokens = phrase.trim().split(/\s+/).filter(Boolean);
  return tokens.map((token) => resolveToken(list, token)).join(" ");
}

/** English prefix expansion (kobe `mnemonic::expand`). */
export function expandMnemonic(phrase: string): string {
  return expandMnemonicWith(english, phrase);
}
