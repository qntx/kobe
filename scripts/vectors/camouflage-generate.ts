// Generates vectors/camouflage.json from source B (this file, node:crypto
// PBKDF2 + @scure/bip39) and asserts byte-equality with the kobe v4.0.0
// binary outputs in /tmp/v4-cases.json (source A, not committed — see the
// note field for reproduction instructions).
import { mnemonicToEntropy, entropyToMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { HDKey } from "@scure/bip32";
import { pbkdf2Sync, createHash } from "node:crypto";

const SALT = "kobe-mnemonic-camouflage-v1";
const ITERATIONS = 600_000;

function transform(phrase: string, password: string): string {
  const entropy = mnemonicToEntropy(phrase, wordlist);
  const key = pbkdf2Sync(Buffer.from(password, "utf8"), SALT, ITERATIONS, entropy.length, "sha256");
  const xor = Uint8Array.from(entropy, (b, i) => b ^ key[i]);
  return entropyToMnemonic(xor, wordlist);
}

function fingerprint(phrase: string): string {
  const seed = require("@scure/bip39").mnemonicToSeedSync(phrase, "");
  const master = HDKey.fromMasterSeed(seed);
  const h160 = createHash("ripemd160")
    .update(createHash("sha256").update(Buffer.from(master.publicKey as Uint8Array)).digest())
    .digest();
  return h160.subarray(0, 4).toString("hex");
}

const v4 = JSON.parse(await Bun.file("/tmp/v4-cases.json").text()) as {
  words: number; password_id: string; password: string; phrase: string; camouflaged: string;
}[];

const vectors = [];
for (const c of v4) {
  const ours = transform(c.phrase, c.password);
  if (ours !== c.camouflaged) throw new Error(`source A/B mismatch ${c.words}/${c.password_id}`);
  vectors.push({
    words: c.words,
    password: c.password,
    phrase: c.phrase,
    camouflaged: ours,
    fingerprint: fingerprint(c.phrase),
  });
}

// Decrypt-only case: the NFD form of "pässwörd" is a *different* password
// byte string than its NFC form — same transform, different result.
const nfc = "pässwörd";
const nfd = "pa\u0308sswo\u0308rd";
if (nfd.normalize("NFC") !== nfc) throw new Error("nfd normalization check");
const nfdVector = {
  words: 12,
  password: nfd,
  phrase: v4.find(c => c.words === 12 && c.password_id === "pässwörd-nfc")!.phrase,
  camouflaged: transform(v4.find(c => c.words === 12 && c.password_id === "pässwörd-nfc")!.phrase, nfd),
  fingerprint: fingerprint(v4.find(c => c.words === 12 && c.password_id === "pässwörd-nfc")!.phrase),
  decrypt_only: true,
  note: "NFD form of 'pässwörd': byte-distinct from NFC, yields a different valid mnemonic (v4-compatible)",
};
vectors.push(nfdVector);

const out = {
  source:
    "Two independent sources, byte-identical: (A) kobe v4.0.0 release binary `kobe mnemonic encrypt --json -r` run in a temporary git worktree at tag v4.0.0; (B) scripts/vectors/camouflage-generate.ts (node:crypto pbkdf2Sync + @scure/bip39). Regenerate B with `bun run camouflage-generate.ts` in scripts/vectors; A outputs were captured to /tmp/v4-cases.json at generation time.",
  note: "Camouflage algorithm v1: E' = E XOR PBKDF2-HMAC-SHA256(password.as_bytes(), 'kobe-mnemonic-camouflage-v1', 600_000, |E|), re-encoded as BIP-39. Passwords are raw UTF-8 bytes; encrypt requires NFC, decrypt is byte-for-byte.",
  vectors,
};
console.log(JSON.stringify(out, null, 2));
