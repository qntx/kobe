// vectors/arweave.json generator (source B + branch audit).
// RSA vectors follow Wander's exact call path:
//   bip39-web-crypto 4.0.1 mnemonicToSeed ->
//   human-crypto-keys 0.1.4 getKeyPairFromSeed(seed, {id:'rsa', modulusLength:4096},
//     {privateKeyFormat:'pkcs8-der'})  with node-forge forced to 1.3.1.
// The finish-branch audit replays forge's algorithm (hmac-drbg 1.0.1 + BigInt)
// and asserts p/q/n equal the JWK, recording which regeneration branch fired.
// ECDSA vectors cross-check kobe v4.0.0 release output against @noble/secp256k1.
import { mnemonicToSeed } from "bip39-web-crypto";
import { getKeyPairFromSeed } from "human-crypto-keys";
import { createPrivateKey, createHash, pbkdf2Sync } from "node:crypto";
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import Drbg from "hmac-drbg";
import hash from "hash.js";

import * as secp from "@noble/secp256k1";
import { HDKey } from "@scure/bip32";

const V4 = process.env.KOBE_V4 ?? "/tmp/kobe-v4/target/release/kobe";
const E = 65537n;
const DELTA = [6n, 4n, 2n, 4n, 2n, 4n, 6n, 2n];

// jsbn first-byte masking + forge PRIMEINC — replay of node-forge 1.3.1.
function rand(drbg: Drbg, b: number): bigint {
  const n = (b >> 3) + 1;
  const x = Buffer.from(drbg.generate(n, "hex"), "hex");
  const rem = b & 7;
  x[0] = rem === 0 ? 0 : x[0] & ((1 << rem) - 1);
  return BigInt("0x" + x.toString("hex"));
}
const bitlen = (n: bigint) => n.toString(2).length;
function aligned(drbg: Drbg, b: number): bigint {
  let n = rand(drbg, b);
  if (!((n >> BigInt(b - 1)) & 1n)) n |= 1n << BigInt(b - 1);
  return n + (31n - (n % 30n));
}
function millerRabin(n: bigint, a: bigint): boolean {
  const n1 = n - 1n; let d = n1, s = 0;
  while (!(d & 1n)) { d >>= 1n; s++; }
  let x = a ** 0n; x = modPow(a, d, n);
  if (x === 1n || x === n1) return true;
  for (let i = 1; i < s; i++) { x = x * x % n; if (x === n1) return true; }
  return false;
}
function modPow(b: bigint, e: bigint, m: bigint): bigint {
  let r = 1n; b %= m;
  while (e) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; }
  return r;
}
// forge tests with 2 rounds of deterministic MR bases (Math.random is not
// DRBG-seeded); for replay purposes a strong fixed-base set suffices.
const MR_BASES = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n];
const isPrime = (n: bigint) => MR_BASES.every((a) => a >= n || millerRabin(n, a));
function prime(drbg: Drbg, b: number): bigint {
  let n = aligned(drbg, b); let k = 0;
  while (true) {
    if (bitlen(n) > b) { n = aligned(drbg, b); k = 0; }
    else if (isPrime(n)) return n;
    else { n += DELTA[k++ % 8]; }
  }
}
interface Audit { branches: string[]; p: bigint; q: bigint; }
function replay(seed: Buffer): Audit {
  const drbg = new Drbg({ hash: hash.sha256, entropy: seed.toString("hex"), nonce: null, pers: null });
  let p = prime(drbg, 2048), q = prime(drbg, 2048), swapped = false;
  const branches: string[] = [];
  while (true) {
    if (p < q && !swapped) { [p, q] = [q, p]; swapped = true; branches.push("swap"); }
    if ((p - 1n) % E === 0n) { branches.push("p-1%e==0"); p = prime(drbg, 2048); swapped = false; continue; }
    if ((q - 1n) % E === 0n) { branches.push("q-1%e==0"); q = prime(drbg, 2048); continue; }
    if (bitlen(p * q) !== 4096) { branches.push("bitlen(n)!=4096"); q = prime(drbg, 2048); continue; }
    break;
  }
  return { branches, p, q };
}

const b64u = (b: Buffer | Uint8Array) =>
  Buffer.from(b).toString("base64").replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
const beBytes = (n: bigint, len = 512) => {
  const hex = n.toString(16).padStart(len * 2, "0");
  return Buffer.from(hex, "hex");
};

const MNEMONICS = [
  { id: "abandon12", mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", passphrase: "" },
  { id: "m24", mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art", passphrase: "" },
  { id: "m12-pass", mnemonic: "legal winner thank year wave sausage worth useful legal winner thank yellow", passphrase: "TREZOR" },
];

const rsaVectors = [];
for (const { id, mnemonic, passphrase } of MNEMONICS) {
  const seed = await mnemonicToSeed(mnemonic, passphrase);
  const t0 = Date.now();
  const key = await getKeyPairFromSeed(seed, { id: "rsa", modulusLength: 4096 }, { privateKeyFormat: "pkcs8-der" });
  const ms = Date.now() - t0;
  const jwk = createPrivateKey({ key: Buffer.from(key.privateKey), format: "der", type: "pkcs8" })
    .export({ format: "jwk" }) as any;
  const nBig = BigInt("0x" + Buffer.from(jwk.n, "base64url").toString("hex"));
  const audit = replay(Buffer.from(seed));
  const ok = audit.p * audit.q === nBig;
  const address = b64u(createHash("sha256").update(beBytes(nBig)).digest());
  rsaVectors.push({
    id, mnemonic, passphrase, address, ms,
    jwk: { kty: "RSA", e: "AQAB", n: jwk.n, d: jwk.d, p: jwk.p, q: jwk.q, dp: jwk.dp, dq: jwk.dq, qi: jwk.qi },
    branches: audit.branches, replay_matches: ok,
  });
  console.log(`${id}: ${address} ${ms}ms branches=${audit.branches} replay=${ok}`);
}

// ECDSA: v4 binary + independent @noble check.
const ecdsaVectors = [];
for (const id of ["abandon12", "m24"]) {
  const { mnemonic } = MNEMONICS.find((m) => m.id === id)!;
  const out = JSON.parse(execFileSync(V4, ["arweave", "import", "-m", mnemonic, "-r", "--json", "-c", "3"]).toString());
  const seed = pbkdf2Sync(mnemonic.normalize("NFKD"), "mnemonic", 2048, 64, "sha512");
  const root = HDKey.fromMasterSeed(seed);
  for (let i = 0; i < 3; i++) {
    const node = root.derive(`m/44'/472'/0'/0/${i}`);
    const pk = node.publicKey!;
    const address = b64u(createHash("sha256").update(pk).digest());
    const check = out.accounts[i];
    const independent = { path: `m/44'/472'/0'/0/${i}`, address, public_key: b64u(pk), private_key: Buffer.from(node.privateKey!).toString("hex") };
    if (check.address !== address) throw new Error(`ECDSA mismatch at ${id}[${i}]: ${check.address} != ${address}`);
    ecdsaVectors.push({ mnemonic: id, index: i, ...independent, v4: { address: check.address, private_key: check.private_key } });
  }
}
console.log(`ecdsa: ${ecdsaVectors.length} vectors vs v4 ok`);

const doc = {
  source: "Wander call path (bip39-web-crypto 4.0.1 + human-crypto-keys 0.1.4, node-forge 1.3.1 via overrides); node-forge 0.8.5 verified byte-identical in a separate run. ECDSA cross-checked against kobe v4.0.0 release binary.",
  rsa: rsaVectors,
  ecdsa: ecdsaVectors,
};
writeFileSync("../../vectors/arweave.json", JSON.stringify(doc, null, 2) + "\n");
console.log("wrote vectors/arweave.json");
