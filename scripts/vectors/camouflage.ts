// Independent SeedQR-camouflage vector generator (source B, per the v7
// design): E' = E XOR PBKDF2-HMAC-SHA256(password, "kobe-mnemonic-
// camouflage-v1", 600_000, |E|) re-encoded as a BIP-39 mnemonic.
// Cross-checked byte-for-byte against the kobe v4.0.0 release binary.
import { mnemonicToEntropy, entropyToMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { pbkdf2Sync, createHash } from "node:crypto";

const SALT = "kobe-mnemonic-camouflage-v1";
const ITERATIONS = 600_000;

export function transform(phrase: string, password: string): string {
  const entropy = mnemonicToEntropy(phrase, wordlist);
  const key = pbkdf2Sync(Buffer.from(password, "utf8"), SALT, ITERATIONS, entropy.length, "sha256");
  const xor = entropy.map((b, i) => b ^ key[i]);
  return entropyToMnemonic(xor, wordlist);
}

export function fingerprint(phrase: string): string {
  // BIP-32 master fingerprint: first 4 bytes of HASH160(compressed
  // master pubkey) — matches kobe::Wallet::fingerprint.
  const { HDKey } = require("@scure/bip32") as typeof import("@scure/bip32");
  const seed = require("@scure/bip39").mnemonicToSeedSync(phrase, "");
  const master = HDKey.fromMasterSeed(seed);
  const h160 = createHash("ripemd160")
    .update(createHash("sha256").update(Buffer.from(master.publicKey as Uint8Array)).digest())
    .digest();
  return h160.subarray(0, 4).toString("hex");
}
