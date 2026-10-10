import { inspect } from "node:util";
import { expect, test } from "vitest";
import {
  accountHashEd25519,
  accountHashSecp256k1,
  casperPath,
  createCasperDeriver,
  formatAccountHash,
  parseCasperAlgo,
  taggedPublicKeyHex,
} from "../../src/chains/casper/index.ts";
import { hexToBytes } from "../../src/crypto/hex.ts";
import { DeriveError } from "../../src/errors/derive.ts";
import { walletFromMnemonic } from "../../src/hd/index.ts";

const ABANDON =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const SECP0_PRIV = "9c72144893c3ca5fa7299e65a7d7d6c41ab6a7add5f9860618324854d3c369d1";
const SECP0_ADDR = "account-hash-e699fcd4904aa6617b2930c6d8995a6f301708b6a64621820a5896d92e2457b3";
const SECP0_TAGGED = "020357f9e27d8125932c5e6fd52babb1a114bc89363f2f56c7860bb594f74523342b";

const ED0_PRIV = "619386127005778f66a68fa91518c0841f59495790bb796fc781ecdd54fe329a";
const ED0_ADDR = "account-hash-356106f683840956a5bff75d011b236068ceccdf09d5c1a6a748c9355b635e08";
const ED0_TAGGED = "016a1585d8197fc14b1d8cc05d5351e5ba04810d466158a050494c799b776ff819";

test("gold: AccountHash ed25519 fixed key (casper-types / hashlib)", () => {
  const pk = hexToBytes("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
  const digest = accountHashEd25519(pk);
  expect(formatAccountHash(digest)).toBe(
    "account-hash-5b1c945c6e0923bf4f8da320444804791eb60d70983c7c5756d8ef236c1fdece",
  );
  expect(taggedPublicKeyHex(0x01, pk)).toBe(
    "010123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  );
});

test("gold: AccountHash secp256k1 generator", () => {
  const pk = hexToBytes("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
  const digest = accountHashSecp256k1(pk);
  expect(formatAccountHash(digest)).toBe(
    "account-hash-86937931937ee0281e50806b94f8d4993e8869b0689dfa0a21d2946ab677183c",
  );
  expect(taggedPublicKeyHex(0x02, pk)).toBe(
    "020279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  );
});

test("gold: Casper secp abandon index 0 (kobe-casper)", () => {
  const w = walletFromMnemonic(ABANDON);
  using a = createCasperDeriver(w).derive(0);
  expect(a.algo).toBe("secp256k1");
  expect(a.path).toBe("m/44'/506'/0'/0/0");
  expect(casperPath("secp256k1", 0)).toBe("m/44'/506'/0'/0/0");
  expect(a.privateKeyHex()).toBe(SECP0_PRIV);
  expect(a.address).toBe(SECP0_ADDR);
  expect(a.accountHash()).toBe(SECP0_ADDR);
  expect(a.taggedPublicKeyHex()).toBe(SECP0_TAGGED);
  expect(a.publicKey.kind).toBe("secp256k1-compressed");
  expect(a.publicKeyHex()).not.toBe(a.taggedPublicKeyHex());
  w.dispose();
});

test("gold: Casper ed25519 abandon index 0 (kobe-casper)", () => {
  const w = walletFromMnemonic(ABANDON);
  using a = createCasperDeriver(w, "ed25519").derive(0);
  expect(a.algo).toBe("ed25519");
  expect(a.path).toBe("m/44'/506'/0'/0'/0'");
  expect(casperPath("ed25519", 0)).toBe("m/44'/506'/0'/0'/0'");
  expect(a.privateKeyHex()).toBe(ED0_PRIV);
  expect(a.address).toBe(ED0_ADDR);
  expect(a.taggedPublicKeyHex()).toBe(ED0_TAGGED);
  w.dispose();
});

test("ed and secp addresses differ; index 1 differs", () => {
  const w = walletFromMnemonic(ABANDON);
  using secp0 = createCasperDeriver(w).derive(0);
  using secp1 = createCasperDeriver(w).derive(1);
  using ed0 = createCasperDeriver(w, "ed25519").derive(0);
  expect(secp0.address).not.toBe(ed0.address);
  expect(secp0.address).not.toBe(secp1.address);
  expect(secp1.path).toBe("m/44'/506'/0'/0/1");
  w.dispose();
});

test("deriveMany matches scalar derive", () => {
  const w = walletFromMnemonic(ABANDON);
  const d = createCasperDeriver(w);
  const batch = d.deriveMany(0, 3);
  for (let i = 0; i < 3; i++) {
    using single = d.derive(i);
    expect(batch[i]!.address).toBe(single.address);
    expect(batch[i]!.taggedPublicKeyHex()).toBe(single.taggedPublicKeyHex());
  }
  for (const a of batch) a.dispose();
  w.dispose();
});

test("passphrase changes address; inspect redacts secret", () => {
  const a = walletFromMnemonic(ABANDON);
  const b = walletFromMnemonic(ABANDON, "TREZOR");
  using aa = createCasperDeriver(a).derive(0);
  using bb = createCasperDeriver(b).derive(0);
  expect(aa.address).not.toBe(bb.address);
  expect(inspect(aa)).toContain("[REDACTED]");
  expect(inspect(aa)).not.toContain(SECP0_PRIV);
  a.dispose();
  b.dispose();
});

test("parseCasperAlgo aliases; unknown throws", () => {
  expect(parseCasperAlgo("SECP")).toBe("secp256k1");
  expect(parseCasperAlgo("ed")).toBe("ed25519");
  expect(() => parseCasperAlgo("rsa")).toThrow(DeriveError);
});
