import { utf8ToBytes } from "@noble/hashes/utils.js";

import type { Pbkdf2 } from "../platform.ts";
import { wipe } from "../secret/secret.ts";
import { mnemonicFromEntropy } from "./mnemonic.ts";

/** BIP-39 seed: PBKDF2-HMAC-SHA512, 2048 rounds, 64 bytes. */
export async function seedFromMnemonic(
  mnemonic: string,
  passphrase: string,
  pbkdf2: Pbkdf2,
): Promise<Uint8Array> {
  const password = utf8ToBytes(mnemonic.normalize("NFKD"));
  const salt = utf8ToBytes(`mnemonic${passphrase}`.normalize("NFKD"));
  try {
    return await pbkdf2("sha512", password, salt, 2048, 64);
  } finally {
    wipe(password, salt);
  }
}

export async function seedFromEntropy(entropy: Uint8Array, pbkdf2: Pbkdf2): Promise<Uint8Array> {
  return seedFromMnemonic(mnemonicFromEntropy(entropy), "", pbkdf2);
}
