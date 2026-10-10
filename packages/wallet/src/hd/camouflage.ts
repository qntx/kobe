/**
 * Mnemonic camouflage (`wallet/hd/camouflage`).
 *
 * Entropy-layer XOR with PBKDF2-HMAC-SHA256. Matches kobe `camouflage` v1.
 * Default `wallet/hd` does not export this surface.
 */
import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from "@scure/bip39";
import { pbkdf2Sha256 } from "../crypto/index.ts";
import { DeriveError } from "../errors/derive.ts";
import { wipeBytes } from "../secret/dispose.ts";
import type { MnemonicLanguage } from "./language.ts";
import { wordlistFor } from "./wordlists.ts";

export type CamouflageVersion = "v1";

/** v1: PBKDF2-HMAC-SHA256, 600_000 iterations, salt `kobe-mnemonic-camouflage-v1`. */
export const CAMOUFLAGE_V1: CamouflageVersion = "v1";

const V1_ITERATIONS = 600_000;
const V1_SALT = new TextEncoder().encode("kobe-mnemonic-camouflage-v1");

function listFor(language: MnemonicLanguage): string[] {
  return wordlistFor(language) as string[];
}

function transform(
  language: MnemonicLanguage,
  phrase: string,
  password: string,
  version: CamouflageVersion,
): string {
  if (password.length === 0) {
    throw new DeriveError("input", "password must not be empty");
  }
  if (version !== "v1") {
    throw new DeriveError("input", `unknown camouflage version '${String(version)}'`);
  }
  const list = listFor(language);
  const normalized = phrase.trim().split(/\s+/).filter(Boolean).join(" ");
  if (!validateMnemonic(normalized, list)) {
    throw new DeriveError("mnemonic", "invalid mnemonic checksum or words");
  }
  const entropy = mnemonicToEntropy(normalized, list);
  const key = pbkdf2Sha256(
    new TextEncoder().encode(password),
    V1_SALT,
    V1_ITERATIONS,
    entropy.length,
  );
  try {
    const next = new Uint8Array(entropy.length);
    for (let i = 0; i < entropy.length; i++) {
      next[i] = (entropy[i] ?? 0) ^ (key[i] ?? 0);
    }
    return entropyToMnemonic(next, list);
  } finally {
    wipeBytes(key);
    wipeBytes(entropy);
  }
}

export function encrypt(phrase: string, password: string): string {
  return transform("english", phrase, password, CAMOUFLAGE_V1);
}

export function decrypt(camouflaged: string, password: string): string {
  return transform("english", camouflaged, password, CAMOUFLAGE_V1);
}

export function encryptIn(
  language: MnemonicLanguage,
  phrase: string,
  password: string,
  version: CamouflageVersion = CAMOUFLAGE_V1,
): string {
  return transform(language, phrase, password, version);
}

export function decryptIn(
  language: MnemonicLanguage,
  camouflaged: string,
  password: string,
  version: CamouflageVersion = CAMOUFLAGE_V1,
): string {
  return transform(language, camouflaged, password, version);
}

export function encryptWith(
  language: MnemonicLanguage,
  phrase: string,
  password: string,
  version: CamouflageVersion,
): string {
  return transform(language, phrase, password, version);
}

export function decryptWith(
  language: MnemonicLanguage,
  camouflaged: string,
  password: string,
  version: CamouflageVersion,
): string {
  return transform(language, camouflaged, password, version);
}
