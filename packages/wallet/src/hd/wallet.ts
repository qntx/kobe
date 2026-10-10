import { utf8 } from "@scure/base";
import {
  entropyToMnemonic,
  generateMnemonic,
  mnemonicToEntropy,
  mnemonicToSeedSync,
  validateMnemonic,
} from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";

import { deriveSecp256k1FromSeed } from "../bip32/index.ts";
import type { DerivedSecp256k1Key } from "../bip32/index.ts";
import { bytesToHex } from "../crypto/hex.ts";
import { sha256Bytes } from "../crypto/index.ts";
import { DeriveError } from "../errors/derive.ts";
import { copyBytes, wipeBytes } from "../secret/dispose.ts";
import { deriveEd25519FromSeed } from "../slip10/index.ts";
import type { DerivedEd25519Key } from "../slip10/index.ts";
import { expandMnemonic } from "./expand.ts";
import type { MnemonicLanguage } from "./language.ts";

export type { MnemonicLanguage } from "./language.ts";
export type WordCount = 12 | 15 | 18 | 21 | 24;

const WORD_COUNT_TO_STRENGTH: Record<WordCount, number> = {
  12: 128,
  15: 160,
  18: 192,
  21: 224,
  24: 256,
};

const ENTROPY_LENS = new Set([16, 20, 24, 28, 32]);

/** Domain separation tag for {@link Wallet.id} — ASCII bytes, no length prefix. */
const WALLET_ID_DOMAIN = new TextEncoder().encode("kobe/wallet-id/v1");

export type Wallet = {
  readonly hasPassphrase: boolean;
  readonly language: MnemonicLanguage;
  readonly wordCount: WordCount;

  /**
   * Stable 16-hex-char identifier: `SHA-256("kobe/wallet-id/v1" ‖ master_pubkey)[..8]` hex, where
   * `master_pubkey` is the 33-byte compressed secp256k1 public key at path `m`. Not secret; safe to
   * persist/log.
   *
   * @throws DeriveError input if disposed
   */
  id(): string;

  /** Fresh UTF-8 mnemonic bytes. Caller owns the copy. @throws if disposed */
  mnemonicBytes(): Uint8Array;
  /** String form (immutable; prefer mnemonicBytes). @throws if disposed */
  mnemonic(): string;

  /** @throws DeriveError path | crypto | input if disposed */
  deriveSecp256k1(path: string): DerivedSecp256k1Key;

  /**
   * SLIP-10 Ed25519. Every path segment after `m` must be hardened (`'`/`h`).
   *
   * @throws DeriveError path | crypto | input if disposed
   */
  deriveEd25519(path: string): DerivedEd25519Key;

  dispose(): void;
  [Symbol.dispose](): void;
  toString(): string;
};

class WalletImpl implements Wallet {
  readonly hasPassphrase: boolean;
  readonly language: MnemonicLanguage;
  readonly wordCount: WordCount;

  #mnemonicUtf8: Uint8Array | undefined;
  #seed: Uint8Array | undefined;
  #disposed = false;

  constructor(
    mnemonicUtf8: Uint8Array,
    seed: Uint8Array,
    hasPassphrase: boolean,
    wordCount: WordCount,
    language: MnemonicLanguage,
  ) {
    this.#mnemonicUtf8 = mnemonicUtf8;
    this.#seed = seed;
    this.hasPassphrase = hasPassphrase;
    this.wordCount = wordCount;
    this.language = language;
  }

  #live(): { mnemonic: Uint8Array; seed: Uint8Array } {
    const mnemonic = this.#mnemonicUtf8;
    const seed = this.#seed;
    if (this.#disposed || mnemonic === undefined || seed === undefined) {
      throw new DeriveError("input", "disposed");
    }
    return { mnemonic, seed };
  }

  mnemonicBytes(): Uint8Array {
    return copyBytes(this.#live().mnemonic);
  }

  mnemonic(): string {
    return utf8.encode(this.#live().mnemonic);
  }

  id(): string {
    const master = deriveSecp256k1FromSeed(this.#live().seed, "m");
    try {
      const payload = new Uint8Array(WALLET_ID_DOMAIN.length + 33);
      payload.set(WALLET_ID_DOMAIN);
      payload.set(master.compressedPublicKey(), WALLET_ID_DOMAIN.length);
      return bytesToHex(sha256Bytes(payload)).slice(0, 16);
    } finally {
      master.dispose();
    }
  }

  seedBytes(): Uint8Array {
    return copyBytes(this.#live().seed);
  }

  deriveSecp256k1(path: string): DerivedSecp256k1Key {
    return deriveSecp256k1FromSeed(this.#live().seed, path);
  }

  deriveEd25519(path: string): DerivedEd25519Key {
    return deriveEd25519FromSeed(this.#live().seed, path);
  }

  dispose(): void {
    if (this.#disposed) {
      return;
    }
    wipeBytes(this.#mnemonicUtf8);
    wipeBytes(this.#seed);
    this.#mnemonicUtf8 = undefined;
    this.#seed = undefined;
    this.#disposed = true;
  }

  [Symbol.dispose](): void {
    this.dispose();
  }

  toString(): string {
    return "Wallet [REDACTED]";
  }

  toJSON(): { wallet: string } {
    return { wallet: "[REDACTED]" };
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return this.toString();
  }
}

function wordCountFromMnemonic(phrase: string): WordCount {
  const n = phrase.trim().split(/\s+/).length;
  if (n === 12 || n === 15 || n === 18 || n === 21 || n === 24) {
    return n;
  }
  throw new DeriveError("mnemonic", `unsupported word count ${n}`);
}

export function buildWalletWith(
  phrase: string,
  passphrase: string,
  list: string[],
  language: MnemonicLanguage,
): Wallet {
  const normalized = phrase.trim().split(/\s+/).filter(Boolean).join(" ");
  if (!validateMnemonic(normalized, list)) {
    throw new DeriveError("mnemonic", "invalid mnemonic checksum or words");
  }
  const seed = mnemonicToSeedSync(normalized, passphrase);
  if (seed.length !== 64) {
    throw new DeriveError("crypto", "unexpected seed length");
  }
  const mnemonicUtf8 = new TextEncoder().encode(normalized);
  return new WalletImpl(
    mnemonicUtf8,
    new Uint8Array(seed),
    passphrase.length > 0,
    wordCountFromMnemonic(normalized),
    language,
  );
}

function buildWallet(phrase: string, passphrase: string): Wallet {
  return buildWalletWith(phrase, passphrase, wordlist, "english");
}

export type GenerateWalletOptions = {
  wordCount?: WordCount;
  passphrase?: string;
  /** Fill the provided buffer with CSPRNG bytes. Defaults to crypto.getRandomValues. */
  rng?: (bytes: Uint8Array) => void;
};

/** @throws DeriveError input (word count) */
export function generateWallet(opts: GenerateWalletOptions = {}): Wallet {
  const wordCount = opts.wordCount ?? 12;
  const strength = WORD_COUNT_TO_STRENGTH[wordCount];
  if (strength === undefined) {
    throw new DeriveError("input", `invalid wordCount ${String(opts.wordCount)}`);
  }
  const passphrase = opts.passphrase ?? "";
  let phrase: string;
  if (opts.rng) {
    const entropy = new Uint8Array(strength / 8);
    opts.rng(entropy);
    phrase = entropyToMnemonic(entropy, wordlist);
    wipeBytes(entropy);
  } else {
    phrase = generateMnemonic(wordlist, strength);
  }
  return buildWallet(phrase, passphrase);
}

/** @throws DeriveError mnemonic */
export function walletFromMnemonic(phrase: string, passphrase = ""): Wallet {
  try {
    return buildWallet(phrase, passphrase);
  } catch (error) {
    if (error instanceof DeriveError) {
      throw error;
    }
    throw new DeriveError("mnemonic", error instanceof Error ? error.message : "invalid mnemonic", {
      cause: error,
    });
  }
}

/** Expand English 4-letter prefixes then import (kobe `from_mnemonic_expanded`). */
export function walletFromMnemonicExpanded(phrase: string, passphrase = ""): Wallet {
  return walletFromMnemonic(expandMnemonic(phrase), passphrase);
}

/** @throws DeriveError mnemonic | input (entropy length) */
export function walletFromEntropy(entropy: Uint8Array, passphrase = ""): Wallet {
  if (!ENTROPY_LENS.has(entropy.length)) {
    throw new DeriveError("input", `entropy length must be 16|20|24|28|32, got ${entropy.length}`);
  }
  try {
    const phrase = entropyToMnemonic(entropy, wordlist);
    return buildWallet(phrase, passphrase);
  } catch (error) {
    if (error instanceof DeriveError) {
      throw error;
    }
    throw new DeriveError("mnemonic", error instanceof Error ? error.message : "invalid entropy", {
      cause: error,
    });
  }
}

/**
 * Fresh 64-byte BIP-39 seed copy. Caller owns it. Public only via `wallet/hd/raw-seed` (kobe
 * `raw-seed` analog).
 *
 * @throws DeriveError input if disposed or not an @qntx/wallet Wallet
 */
export function walletSeedBytes(wallet: Wallet): Uint8Array {
  if (!(wallet instanceof WalletImpl)) {
    throw new DeriveError("input", "wallet seed: not an @qntx/wallet Wallet");
  }
  return wallet.seedBytes();
}

/** Validate BIP-39 English mnemonic without constructing a wallet. */
export function isValidMnemonic(phrase: string): boolean {
  return validateMnemonic(phrase.trim().replaceAll(/\s+/g, " "), wordlist);
}

/** Entropy bytes from a valid mnemonic (for tests / advanced). @throws DeriveError */
export function mnemonicToEntropyBytes(phrase: string): Uint8Array {
  const normalized = phrase.trim().replaceAll(/\s+/g, " ");
  if (!validateMnemonic(normalized, wordlist)) {
    throw new DeriveError("mnemonic", "invalid mnemonic checksum or words");
  }
  return mnemonicToEntropy(normalized, wordlist);
}
