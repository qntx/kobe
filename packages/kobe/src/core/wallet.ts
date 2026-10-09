import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes } from "@noble/hashes/utils.js";
import {
  entropyToMnemonic,
  generateMnemonic,
  mnemonicToSeedSync,
  validateMnemonic,
} from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";

import { deriveSecp256k1FromSeed } from "./bip32.ts";
import type { DerivedSecp256k1Key } from "./bip32.ts";
import { copyBytes, wipeBytes } from "./bytes.ts";
import { KobeError } from "./error.ts";
import { expandMnemonic } from "./expand.ts";

export type WordCount = 12 | 15 | 18 | 21 | 24;

export type GenerateWalletOptions = {
  wordCount?: WordCount;
  passphrase?: string;
  /** Fill the provided buffer with CSPRNG bytes. Defaults to `crypto.getRandomValues`. */
  rng?: (bytes: Uint8Array) => void;
};

const WORD_COUNT_TO_STRENGTH: Record<WordCount, number> = {
  12: 128,
  15: 160,
  18: 192,
  21: 224,
  24: 256,
};

const ENTROPY_LENS = new Set([16, 20, 24, 28, 32]);

/** Domain separation tag for {@link Wallet.id} — ASCII bytes, no length prefix. */
const WALLET_ID_DOMAIN = asciiBytes("kobe/wallet-id/v1");

type WalletSecrets = {
  /** Normalized mnemonic phrase as ASCII bytes (English words only). */
  mnemonic: Uint8Array;
  /** 64-byte BIP-39 seed. */
  seed: Uint8Array;
};

// Secrets live outside the instance so `dispose()` can drop the reference and
// `walletSeed` can read them without a public accessor.
const secrets = new WeakMap<Wallet, WalletSecrets>();

function asciiBytes(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) {
    // English words are ASCII; `?? 0` only satisfies the `undefined` return type.
    out[i] = text.codePointAt(i) ?? 0;
  }
  return out;
}

/** Normalize phrase whitespace: any whitespace run → single space, trimmed. */
function normalizePhrase(phrase: string): string {
  return phrase.trim().split(/\s+/).filter(Boolean).join(" ");
}

function isWordCount(n: number): n is WordCount {
  return n === 12 || n === 15 || n === 18 || n === 21 || n === 24;
}

/**
 * A unified HD wallet holding a BIP-39 English mnemonic and the derived 64-byte seed used by
 * {@link Wallet.deriveSecp256k1} (and the chain derivers built on it, e.g. `@qntx/kobe/nostr`).
 *
 * Mnemonic and seed live in a module-scoped WeakMap; {@link Wallet.dispose} wipes both buffers and
 * every subsequent secret accessor throws `KobeError("input")`. `toString` / `toJSON` are redacted;
 * secrets live in private state, so `util.inspect` never shows them.
 */
export class Wallet {
  /** Number of mnemonic words (12–24). */
  readonly wordCount: WordCount;
  /** Whether a non-empty passphrase was supplied at construction time. */
  readonly hasPassphrase: boolean;

  private constructor(
    mnemonic: Uint8Array,
    seed: Uint8Array,
    hasPassphrase: boolean,
    wordCount: WordCount,
  ) {
    secrets.set(this, { mnemonic, seed });
    this.hasPassphrase = hasPassphrase;
    this.wordCount = wordCount;
  }

  /** @throws KobeError mnemonic */
  private static build(phrase: string, passphrase: string): Wallet {
    const normalized = normalizePhrase(phrase);
    if (!validateMnemonic(normalized, wordlist)) {
      throw new KobeError("mnemonic", "invalid mnemonic checksum or words");
    }
    const seed = mnemonicToSeedSync(normalized, passphrase);
    // `validateMnemonic` guarantees a BIP-39 word count.
    const count = normalized.split(" ").length;
    if (!isWordCount(count)) {
      throw new KobeError("mnemonic", `unexpected word count ${count}`);
    }
    return new Wallet(asciiBytes(normalized), seed, passphrase.length > 0, count);
  }

  /**
   * Generate a new wallet with a random mnemonic.
   *
   * @throws KobeError input (word count)
   */
  static generate(options: GenerateWalletOptions = {}): Wallet {
    const wordCount = options.wordCount ?? 12;
    const strength = WORD_COUNT_TO_STRENGTH[wordCount];
    if (strength === undefined) {
      throw new KobeError("input", `invalid wordCount ${String(options.wordCount)}`);
    }
    const passphrase = options.passphrase ?? "";
    let phrase: string;
    if (options.rng) {
      const entropy = new Uint8Array(strength / 8);
      options.rng(entropy);
      try {
        phrase = entropyToMnemonic(entropy, wordlist);
      } finally {
        wipeBytes(entropy);
      }
    } else {
      phrase = generateMnemonic(wordlist, strength);
    }
    return Wallet.build(phrase, passphrase);
  }

  /**
   * Create a wallet from an existing BIP-39 English mnemonic phrase. Whitespace runs collapse to
   * single spaces; no case folding.
   *
   * @throws KobeError mnemonic
   */
  static fromMnemonic(phrase: string, passphrase = ""): Wallet {
    try {
      return Wallet.build(phrase, passphrase);
    } catch (error) {
      if (error instanceof KobeError) {
        throw error;
      }
      throw new KobeError("mnemonic", error instanceof Error ? error.message : "invalid mnemonic", {
        cause: error,
      });
    }
  }

  /**
   * Expand English 4-letter prefixes then import (`kobe_core`'s `Wallet::from_mnemonic_expanded`
   * analog).
   *
   * @throws KobeError input (prefix expansion) | mnemonic
   */
  static fromMnemonicExpanded(phrase: string, passphrase = ""): Wallet {
    return Wallet.fromMnemonic(expandMnemonic(phrase), passphrase);
  }

  /**
   * Create a wallet from raw entropy bytes (16, 20, 24, 28, or 32 bytes).
   *
   * @throws KobeError input (entropy length) | mnemonic
   */
  static fromEntropy(entropy: Uint8Array, passphrase = ""): Wallet {
    if (!ENTROPY_LENS.has(entropy.length)) {
      throw new KobeError("input", `entropy length must be 16|20|24|28|32, got ${entropy.length}`);
    }
    try {
      return Wallet.build(entropyToMnemonic(entropy, wordlist), passphrase);
    } catch (error) {
      if (error instanceof KobeError) {
        throw error;
      }
      throw new KobeError("mnemonic", error instanceof Error ? error.message : "invalid entropy", {
        cause: error,
      });
    }
  }

  #secrets(): WalletSecrets {
    const s = secrets.get(this);
    if (!s) {
      throw new KobeError("input", "disposed");
    }
    return s;
  }

  /** Fresh mnemonic bytes. Caller owns the copy. @throws KobeError input if disposed */
  mnemonicBytes(): Uint8Array {
    return copyBytes(this.#secrets().mnemonic);
  }

  /** The normalized mnemonic phrase. @throws KobeError input if disposed */
  mnemonic(): string {
    // oxlint-disable-next-line unicorn/prefer-code-point -- ASCII bytes; identical to codePoint
    return String.fromCharCode(...this.#secrets().mnemonic);
  }

  /**
   * Derive a BIP-32 secp256k1 key pair at the given path (e.g. `m/44'/60'/0'/0/0`).
   *
   * @throws KobeError path | crypto | input if disposed
   */
  deriveSecp256k1(path: string): DerivedSecp256k1Key {
    return deriveSecp256k1FromSeed(this.#secrets().seed, path);
  }

  /**
   * Stable, non-secret wallet identifier: the first 16 hex chars (8 bytes) of
   * `SHA-256("kobe/wallet-id/v1" ‖ master_pubkey)`, where `master_pubkey` is the 33-byte compressed
   * secp256k1 public key of the BIP-32 root node (`m`) over the BIP-39 seed. The domain separator
   * is concatenated as raw UTF-8 bytes — no length prefix.
   *
   * The id commits to the whole wallet (mnemonic + passphrase) without revealing key material and
   * is safe to expose.
   *
   * @throws KobeError path | crypto | input if disposed
   */
  id(): string {
    const key = this.deriveSecp256k1("m");
    try {
      return bytesToHex(sha256(concatBytes(WALLET_ID_DOMAIN, key.compressedPublicKey()))).slice(
        0,
        16,
      );
    } finally {
      key.dispose();
    }
  }

  /** Wipe the mnemonic and the seed. Idempotent. */
  dispose(): void {
    const s = secrets.get(this);
    if (!s) {
      return;
    }
    wipeBytes(s.mnemonic);
    wipeBytes(s.seed);
    secrets.delete(this);
  }

  toString(): string {
    return "Wallet [REDACTED]";
  }

  toJSON(): { wallet: string } {
    return { wallet: "[REDACTED]" };
  }
}

/**
 * Fresh 64-byte BIP-39 seed copy; the caller owns it.
 *
 * Internal module export — not re-exported from the package index. Used by the shared-vector
 * runner.
 *
 * @throws KobeError input if the wallet is disposed or was not produced by
 * this module
 */
export function walletSeed(wallet: Wallet): Uint8Array {
  const s = secrets.get(wallet);
  if (!s) {
    throw new KobeError("input", "wallet seed: disposed or not a Wallet");
  }
  return copyBytes(s.seed);
}

/** Validate a BIP-39 English mnemonic without constructing a wallet. */
export function isValidMnemonic(phrase: string): boolean {
  return validateMnemonic(normalizePhrase(phrase), wordlist);
}
